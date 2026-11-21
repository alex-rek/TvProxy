package com.glaude.tvproxy.net

import java.io.IOException
import java.net.Socket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.min

/**
 * Одно TCP-соединение приложения. Со стороны TUN мы играем роль удалённого сервера
 * (упрощённый TCP-стек), со стороны сети — обычный Socket через прокси.
 */
class TcpSession(
    private val engine: TunEngine,
    val key: String,
    private val local: ByteArray, private val localPort: Int,
    private val remote: ByteArray, private val remotePort: Int,
    clientIsn: Int, clientMss: Int, clientWindow: Int,
) {
    private enum class State { CONNECTING, SYN_ACK_SENT, ESTABLISHED, CLOSED }

    private val lock = Object()
    private var state = State.CONNECTING

    private val mss = min(if (clientMss > 0) clientMss else 536, if (local.size == 4) 1460 else 1440)
    private val isn = ThreadLocalRandom.current().nextInt()

    // Передача (сервер -> приложение)
    private var sndUna = isn + 1          // самый старый неподтверждённый байт
    private var sndNxtOff = 0             // смещение следующего байта к отправке от sndUna
    private val sendBuf = ByteQueue()     // данные начиная с sndUna
    private var clientWnd = clientWindow
    private var upEof = false
    private var finSent = false
    private var finAcked = false
    private var finSeq = 0
    private var lastProgress = 0L
    private var rto = RTO_MIN
    private var retries = 0
    private var dupAcks = 0
    private var isPureAck = false
    private var retransmits = 0
    private var bytesDown = 0L

    // Приём (приложение -> сервер)
    private var rcvNxt = clientIsn + 1
    private var clientFin = false
    private val writeQueue = LinkedBlockingQueue<ByteArray>()
    private val queued = AtomicInteger(0)

    @Volatile private var socket: Socket? = null
    @Volatile var lastActivity = System.currentTimeMillis(); private set

    // ---------- Подключение к цели через прокси ----------

    fun connectUpstream() {
        val s = try {
            engine.connector.connect(remote, null, remotePort)
        } catch (e: IOException) {
            engine.log("TCP ${engine.fmt(remote)}:$remotePort — ${e.message}")
            synchronized(lock) {
                if (state != State.CLOSED) {
                    engine.writeTun(PacketBuilder.tcp(remote, remotePort, local, localPort, 0, rcvNxt, Proto.RST or Proto.ACK, 0))
                    closeLocked(false)
                }
            }
            return
        }
        synchronized(lock) {
            if (state == State.CLOSED) { runCatching { s.close() }; return }
            socket = s
            state = State.SYN_ACK_SENT
            lastProgress = System.currentTimeMillis()
            sendSynAck()
        }
    }

    private fun sendSynAck() {
        engine.writeTun(PacketBuilder.tcp(remote, remotePort, local, localPort, isn, rcvNxt,
            Proto.SYN or Proto.ACK, advWindow(), mss = mss))
    }

    private fun startIo() {
        val s = socket ?: return
        engine.executor.execute { readerLoop(s) }
        engine.executor.execute { writerLoop(s) }
    }

    // ---------- Пакеты от приложения ----------

    fun onPacket(p: IpPacket) {
        synchronized(lock) {
            if (state == State.CLOSED) return
            lastActivity = System.currentTimeMillis()
            val flags = p.tcpFlags
            if (flags and Proto.RST != 0) { closeLocked(false); return }
            if (flags and Proto.SYN != 0) {
                if (state == State.SYN_ACK_SENT) sendSynAck()
                return
            }
            if (state == State.CONNECTING) return
            if (flags and Proto.ACK == 0) return

            val ack = p.tcpAck
            if (state == State.SYN_ACK_SENT) {
                if (ack != isn + 1) return
                state = State.ESTABLISHED
                rto = RTO_MIN
                retries = 0
                startIo()
            }
            val seq = p.tcpSeq
            val len = p.tcpPayloadLen
            val wnd = p.tcpWindow
            isPureAck = len == 0 && flags and Proto.FIN == 0 && wnd == clientWnd
            clientWnd = wnd
            handleAck(ack)

            var needAck = false
            var accepted = false
            if (len > 0) {
                if (seq == rcvNxt && !clientFin) {
                    if (queued.get() + len <= WQ_MAX) {
                        writeQueue.offer(p.buf.copyOfRange(p.tcpPayloadOff, p.tcpPayloadOff + len))
                        queued.addAndGet(len)
                        rcvNxt += len
                        accepted = true
                    }
                }
                needAck = true
            }
            if (flags and Proto.FIN != 0) {
                // FIN в порядке очереди: все данные этого сегмента приняты и seq совпадает.
                if (!clientFin && (len == 0 || accepted) && seq + len == rcvNxt) {
                    rcvNxt += 1
                    clientFin = true
                    writeQueue.offer(EOF)
                }
                needAck = true
            }
            if (needAck) sendAck()
            pump()
            checkDone()
        }
    }

    private fun handleAck(ack: Int) {
        if (finSent && ack == finSeq + 1) {
            sendBuf.drop(sendBuf.size)
            sndUna = ack
            sndNxtOff = 0
            finAcked = true
            progress()
            return
        }
        val acked = ack - sndUna
        if (acked > 0 && acked <= sendBuf.size) {
            sendBuf.drop(acked)
            sndUna = ack
            sndNxtOff = maxOf(0, sndNxtOff - acked)
            progress()
            lock.notifyAll()
        } else if (acked == 0 && isPureAck && sndNxtOff > 0) {
            // Повторный ACK — приложение потеряло сегмент. После 3-х шлём его заново сразу.
            if (++dupAcks == 3) retransmitFirst()
        }
    }

    private fun progress() {
        lastProgress = System.currentTimeMillis()
        rto = RTO_MIN
        retries = 0
        dupAcks = 0
    }

    /** Повторно отправить самый старый неподтверждённый сегмент (или FIN). */
    private fun retransmitFirst() {
        retransmits++
        val n = min(mss, min(sendBuf.size, sndNxtOff))
        if (n > 0) {
            engine.writeTun(PacketBuilder.tcp(remote, remotePort, local, localPort,
                sndUna, rcvNxt, Proto.ACK or Proto.PSH, advWindow(), sendBuf.peek(0, n), 0, n))
        } else if (finSent && !finAcked) {
            engine.writeTun(PacketBuilder.tcp(remote, remotePort, local, localPort,
                finSeq, rcvNxt, Proto.FIN or Proto.ACK, advWindow()))
        }
    }

    private fun advWindow(): Int = (WQ_MAX - queued.get()).coerceIn(0, 65535)

    private fun sendAck() {
        engine.writeTun(PacketBuilder.tcp(remote, remotePort, local, localPort,
            sndUna + sndNxtOff + (if (finSent && sndNxtOff == sendBuf.size) 1 else 0), rcvNxt, Proto.ACK, advWindow()))
    }

    /** Отправить в TUN всё, что позволяет окно приложения. Вызывать под lock. */
    private fun pump() {
        if (state != State.ESTABLISHED) return
        val wasIdle = sndNxtOff == 0
        while (true) {
            val avail = sendBuf.size - sndNxtOff
            val canSend = clientWnd - sndNxtOff
            if (avail <= 0 || canSend <= 0) break
            val n = min(mss, min(avail, canSend))
            val data = sendBuf.peek(sndNxtOff, n)
            engine.writeTun(PacketBuilder.tcp(remote, remotePort, local, localPort,
                sndUna + sndNxtOff, rcvNxt, Proto.ACK or Proto.PSH, advWindow(), data, 0, n))
            sndNxtOff += n
        }
        if (upEof && !finSent && sndNxtOff == sendBuf.size) {
            finSeq = sndUna + sendBuf.size
            finSent = true
            engine.writeTun(PacketBuilder.tcp(remote, remotePort, local, localPort,
                finSeq, rcvNxt, Proto.FIN or Proto.ACK, advWindow()))
        }
        if (wasIdle && (sndNxtOff > 0 || finSent)) lastProgress = System.currentTimeMillis()
    }

    private fun checkDone() {
        if (clientFin && finAcked) closeLocked(false)
    }

    // ---------- Потоки сокета ----------

    private fun readerLoop(s: Socket) {
        val tmp = ByteArray(32 * 1024)
        try {
            val inp = s.getInputStream()
            while (true) {
                synchronized(lock) {
                    while (state != State.CLOSED && sendBuf.size >= SEND_BUF_MAX) lock.wait(1000)
                    if (state == State.CLOSED) return
                }
                val n = inp.read(tmp)
                synchronized(lock) {
                    if (state == State.CLOSED) return
                    lastActivity = System.currentTimeMillis()
                    if (n < 0) {
                        upEof = true
                        pump()
                        checkDone()
                        return
                    }
                    sendBuf.append(tmp, 0, n)
                    bytesDown += n
                    pump()
                }
            }
        } catch (e: Exception) {
            synchronized(lock) { if (state != State.CLOSED) closeLocked(true) }
        }
    }

    private fun writerLoop(s: Socket) {
        try {
            val out = s.getOutputStream()
            while (true) {
                val d = writeQueue.take()
                if (d === EOF) { runCatching { s.shutdownOutput() }; return }
                if (d === STOP) return
                out.write(d)
                val before = queued.getAndAdd(-d.size)
                // Окно было почти закрыто — сообщаем приложению, что можно слать дальше.
                if (WQ_MAX - before < 16 * 1024) synchronized(lock) { if (state == State.ESTABLISHED) sendAck() }
            }
        } catch (e: Exception) {
            synchronized(lock) { if (state != State.CLOSED) closeLocked(true) }
        }
    }

    // ---------- Таймер ----------

    fun tick(now: Long) {
        synchronized(lock) {
            when (state) {
                State.CLOSED, State.CONNECTING -> {}
                State.SYN_ACK_SENT -> if (now - lastProgress > rto) {
                    if (++retries > MAX_RETRIES) { closeLocked(true); return }
                    rto = min(rto * 2, RTO_MAX); lastProgress = now
                    sendSynAck()
                }
                State.ESTABLISHED -> {
                    val outstanding = sndNxtOff > 0 || (finSent && !finAcked)
                    if (outstanding && now - lastProgress > rto) {
                        if (++retries > MAX_RETRIES) { closeLocked(true); return }
                        rto = min(rto * 2, RTO_MAX)
                        retransmitFirst()
                        lastProgress = now
                    }
                }
            }
            if (state != State.CLOSED && now - lastActivity > IDLE_TIMEOUT) closeLocked(true)
        }
    }

    fun close() = synchronized(lock) { if (state != State.CLOSED) closeLocked(true) }

    private fun closeLocked(sendRst: Boolean) {
        if (sendRst && state != State.CONNECTING) {
            engine.writeTun(PacketBuilder.tcp(remote, remotePort, local, localPort,
                sndUna + sndNxtOff, rcvNxt, Proto.RST or Proto.ACK, 0))
        }
        if (bytesDown > 0 || retransmits > 0)
            android.util.Log.d(TunEngine.TAG, "close ${engine.fmt(remote)}:$remotePort down=$bytesDown retx=$retransmits rst=$sendRst")
        state = State.CLOSED
        runCatching { socket?.close() }
        writeQueue.clear()
        writeQueue.offer(STOP)
        lock.notifyAll()
        engine.remove(this)
    }

    companion object {
        private val EOF = ByteArray(0)
        private val STOP = ByteArray(0)
        private const val WQ_MAX = 256 * 1024
        private const val SEND_BUF_MAX = 512 * 1024
        private const val RTO_MIN = 400L
        private const val RTO_MAX = 16000L
        private const val MAX_RETRIES = 7
        private const val IDLE_TIMEOUT = 15 * 60 * 1000L
    }
}

/** Простой растущий буфер-очередь байтов. */
class ByteQueue {
    private var buf = ByteArray(64 * 1024)
    private var start = 0
    private var end = 0
    val size get() = end - start

    fun append(src: ByteArray, off: Int, len: Int) {
        if (end + len > buf.size) {
            val need = size + len
            if (need > buf.size) {
                var cap = buf.size
                while (cap < need) cap *= 2
                val nb = ByteArray(cap)
                System.arraycopy(buf, start, nb, 0, size)
                buf = nb
            } else {
                System.arraycopy(buf, start, buf, 0, size)
            }
            end = size; start = 0
        }
        System.arraycopy(src, off, buf, end, len)
        end += len
    }

    fun peek(off: Int, len: Int): ByteArray = buf.copyOfRange(start + off, start + off + len)

    fun drop(n: Int) {
        start += n
        if (start >= end) { start = 0; end = 0 }
    }
}
