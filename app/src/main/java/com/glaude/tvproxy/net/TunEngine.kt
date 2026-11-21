package com.glaude.tvproxy.net

import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Читает IP-пакеты из TUN и раздаёт их TCP-сессиям и DNS-форвардеру. */
class TunEngine(
    private val tun: ParcelFileDescriptor,
    val connector: ProxyConnector,
    private val dns: DnsForwarder.Settings,
    udpViaSocks: Boolean,
    private val onLog: (String) -> Unit,
) {
    private val counter = AtomicInteger()
    val executor: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "tvproxy-io-${counter.incrementAndGet()}").apply { isDaemon = true }
    }
    private val timer: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "tvproxy-timer").apply { isDaemon = true }
    }
    private val sessions = ConcurrentHashMap<String, TcpSession>()
    private val out = FileOutputStream(tun.fileDescriptor)
    private val dnsForwarder = DnsForwarder(this, dns)
    private val udpRelay: UdpRelay? = if (udpViaSocks) UdpRelay(this, dns.protectUdp) else null
    @Volatile private var running = false
    private var thread: Thread? = null

    val activeConnections get() = sessions.size

    fun start() {
        running = true
        thread = Thread({ readLoop() }, "tvproxy-tun").apply { isDaemon = true; start() }
        timer.scheduleWithFixedDelay({
            val now = System.currentTimeMillis()
            for (s in sessions.values) runCatching { s.tick(now) }
            runCatching { udpRelay?.tick(now) }
        }, 250, 250, TimeUnit.MILLISECONDS)
    }

    fun stop() {
        running = false
        for (s in sessions.values) runCatching { s.close() }
        sessions.clear()
        dnsForwarder.close()
        udpRelay?.close()
        timer.shutdownNow()
        executor.shutdownNow()
        thread?.interrupt()
    }

    private fun readLoop() {
        val inp = FileInputStream(tun.fileDescriptor)
        val buf = ByteArray(65536)
        while (running) {
            val n = try { inp.read(buf) } catch (e: Exception) { if (running) log("TUN: ${e.message}"); break }
            if (n < 0) break
            if (n == 0) continue
            try {
                val p = IpPacket(buf.copyOf(n), n)
                if (!p.parse()) continue
                when (p.proto) {
                    Proto.TCP -> onTcp(p)
                    Proto.UDP -> when {
                        p.dstPort == 53 -> dnsForwarder.handle(p)
                        udpRelay != null -> udpRelay.handle(p)
                        // Без SOCKS5-UDP прочий UDP (QUIC и т.п.) отбрасываем — приложения откатятся на TCP.
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "packet error", e)
            }
        }
    }

    private fun onTcp(p: IpPacket) {
        if (p.l4Len < 20) return
        val key = key(p)
        val s = sessions[key]
        if (s != null) { s.onPacket(p); return }
        val flags = p.tcpFlags
        // Виртуальный DNS-адрес (DoT/DNS-over-TCP к нему) — сразу отказ, чтобы система откатилась на UDP.
        val toVirtualDns = p.dst.size == 4 && p.dst.contentEquals(VIRTUAL_DNS)
        if (!toVirtualDns && flags and Proto.SYN != 0 && flags and Proto.ACK == 0) {
            val ns = TcpSession(this, key, p.src, p.srcPort, p.dst, p.dstPort, p.tcpSeq, p.tcpMss(), p.tcpWindow)
            sessions[key] = ns
            try { executor.execute { ns.connectUpstream() } } catch (_: Exception) { sessions.remove(key) }
        } else if (flags and Proto.RST == 0) {
            // Неизвестное соединение — сбрасываем.
            val rst = if (flags and Proto.ACK != 0)
                PacketBuilder.tcp(p.dst, p.dstPort, p.src, p.srcPort, p.tcpAck, 0, Proto.RST, 0)
            else
                PacketBuilder.tcp(p.dst, p.dstPort, p.src, p.srcPort, 0,
                    p.tcpSeq + p.tcpPayloadLen + (if (flags and Proto.FIN != 0) 1 else 0), Proto.RST or Proto.ACK, 0)
            writeTun(rst)
        }
    }

    fun remove(s: TcpSession) { sessions.remove(s.key, s) }

    fun writeTun(pkt: ByteArray) {
        if (!running) return
        try {
            synchronized(out) { out.write(pkt) }
        } catch (e: Exception) {
            Log.w(TAG, "tun write: ${e.message}")
        }
    }

    fun log(msg: String) { Log.i(TAG, msg); onLog(msg) }

    fun fmt(a: ByteArray): String = runCatching { InetAddress.getByAddress(a).hostAddress!! }.getOrDefault("?")

    private fun key(p: IpPacket): String {
        val sb = StringBuilder(48)
        for (b in p.src) sb.append(b.toInt() and 0xFF).append('.')
        sb.append(p.srcPort).append('>')
        for (b in p.dst) sb.append(b.toInt() and 0xFF).append('.')
        sb.append(p.dstPort)
        return sb.toString()
    }

    companion object {
        const val TAG = "TvProxy"
        private val VIRTUAL_DNS = byteArrayOf(10, 111, 0, 2)
    }
}
