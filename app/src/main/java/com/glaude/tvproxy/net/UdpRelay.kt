package com.glaude.tvproxy.net

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * UDP через SOCKS5 (UDP ASSOCIATE). На каждый локальный UDP-сокет приложения
 * (src ip:port) — своя ассоциация: управляющее TCP-соединение + DatagramSocket к реле.
 * Одна ассоциация обслуживает любые адреса назначения.
 */
class UdpRelay(
    private val engine: TunEngine,
    private val protectUdp: (DatagramSocket) -> Boolean,
) {
    private val sessions = ConcurrentHashMap<String, Session>()
    @Volatile private var disabledUntil = 0L

    fun handle(p: IpPacket) {
        val len = p.udpPayloadLen
        if (len < 0 || p.udpPayloadOff + len > p.len) return
        val now = System.currentTimeMillis()
        if (now < disabledUntil) return // сервер недавно отказал в UDP — не долбим его
        val key = engine.fmt(p.src) + "#" + p.srcPort
        var s = sessions[key]
        if (s == null) {
            s = Session(key, p.src, p.srcPort)
            if (sessions.putIfAbsent(key, s) != null) s = sessions[key]!! else s.start()
        }
        s.send(p.dst, p.dstPort, p.buf, p.udpPayloadOff, len)
    }

    fun tick(now: Long) {
        for (s in sessions.values) if (now - s.lastActivity > IDLE_MS) s.close()
    }

    fun close() {
        for (s in sessions.values) s.close()
        sessions.clear()
    }

    private inner class Session(val key: String, val local: ByteArray, val localPort: Int) {
        private val lock = Object()
        private var ready = false
        @Volatile private var closed = false
        private val pending = ArrayList<ByteArray>()
        private var ds: DatagramSocket? = null
        private var control: java.net.Socket? = null
        @Volatile var lastActivity = System.currentTimeMillis()

        fun start() {
            try { engine.executor.execute { connect() } } catch (_: Exception) { close() }
        }

        private fun connect() {
            try {
                val a = engine.connector.udpAssociate()
                val sock = DatagramSocket()
                protectUdp(sock)
                sock.connect(a.relay)
                synchronized(lock) {
                    if (closed) { runCatching { sock.close(); a.control.close() }; return }
                    ds = sock; control = a.control; ready = true
                    for (pkt in pending) runCatching { sock.send(DatagramPacket(pkt, pkt.size)) }
                    pending.clear()
                }
                engine.executor.execute { receiveLoop(sock) }
                engine.executor.execute { watchControl(a.control) }
            } catch (e: Exception) {
                engine.log("UDP — ${e.message}")
                disabledUntil = System.currentTimeMillis() + 30_000
                close()
            }
        }

        fun send(dst: ByteArray, port: Int, data: ByteArray, off: Int, len: Int) {
            lastActivity = System.currentTimeMillis()
            // Заголовок SOCKS5 UDP: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
            val hdr = 4 + dst.size + 2
            val pkt = ByteArray(hdr + len)
            pkt[3] = if (dst.size == 4) 1 else 4
            System.arraycopy(dst, 0, pkt, 4, dst.size)
            pkt[4 + dst.size] = (port ushr 8).toByte()
            pkt[5 + dst.size] = port.toByte()
            System.arraycopy(data, off, pkt, hdr, len)
            synchronized(lock) {
                if (closed) return
                if (!ready) { if (pending.size < 32) pending += pkt; return }
                runCatching { ds!!.send(DatagramPacket(pkt, pkt.size)) }
            }
        }

        private fun receiveLoop(sock: DatagramSocket) {
            val buf = ByteArray(65535)
            val dp = DatagramPacket(buf, buf.size)
            try {
                while (!closed) {
                    dp.length = buf.size
                    sock.receive(dp)
                    val n = dp.length
                    if (n < 10 || buf[2].toInt() != 0) continue // фрагменты SOCKS не поддерживаем
                    val alen = when (buf[3].toInt()) { 1 -> 4; 4 -> 16; else -> continue }
                    if (n < 4 + alen + 2) continue
                    val src = buf.copyOfRange(4, 4 + alen)
                    if (src.size != local.size) continue // ответ другого семейства IP — некуда доставить
                    val sport = ((buf[4 + alen].toInt() and 0xFF) shl 8) or (buf[5 + alen].toInt() and 0xFF)
                    val payload = buf.copyOfRange(6 + alen, n)
                    lastActivity = System.currentTimeMillis()
                    engine.writeTun(PacketBuilder.udp(src, sport, local, localPort, payload))
                }
            } catch (_: Exception) {
            } finally { close() }
        }

        /** Ассоциация живёт, пока открыто управляющее TCP-соединение. */
        private fun watchControl(c: java.net.Socket) {
            try { while (c.getInputStream().read() >= 0) { } } catch (_: Exception) { }
            close()
        }

        fun close() {
            synchronized(lock) {
                if (closed) return
                closed = true
                pending.clear()
            }
            runCatching { ds?.close() }
            runCatching { control?.close() }
            sessions.remove(key, this)
        }
    }

    companion object {
        private const val IDLE_MS = 120_000L

        /** Проверка: DNS-запрос по UDP через реле. Возвращает время ответа в мс. */
        fun selfTest(connector: ProxyConnector, protectUdp: (DatagramSocket) -> Boolean = { true }): Long {
            val a = connector.udpAssociate()
            a.control.use {
                DatagramSocket().use { ds ->
                    protectUdp(ds)
                    ds.soTimeout = 5000
                    ds.connect(a.relay)
                    // A-запрос example.com к 1.1.1.1:53
                    val q = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                        7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
                        'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
                        3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0, 0, 1, 0, 1)
                    val hdr = byteArrayOf(0, 0, 0, 1) + InetAddress.getByName("1.1.1.1").address + byteArrayOf(0, 53)
                    val t0 = System.currentTimeMillis()
                    val out = hdr + q
                    ds.send(DatagramPacket(out, out.size))
                    val buf = ByteArray(2048)
                    val dp = DatagramPacket(buf, buf.size)
                    try { ds.receive(dp) } catch (e: java.net.SocketTimeoutException) {
                        throw java.io.IOException("нет ответа через UDP-реле ${a.relay.address.hostAddress}:${a.relay.port}")
                    }
                    if (dp.length < 10 + 12 || buf[10].toInt() != 0x12 || buf[11].toInt() != 0x34)
                        throw java.io.IOException("неверный ответ UDP-реле")
                    return System.currentTimeMillis() - t0
                }
            }
        }
    }
}
