package com.glaude.tvproxy.net

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Перехватывает DNS-запросы (UDP:53) выбранных приложений и отправляет их
 * на заданный DNS-сервер — через прокси (DNS over TCP) или напрямую.
 */
class DnsForwarder(private val engine: TunEngine, private val s: Settings) {

    class Settings(
        val server: String,
        val viaProxy: Boolean,
        val protectUdp: (DatagramSocket) -> Boolean,
    )

    private class Entry(val data: ByteArray, val expires: Long)

    private val cache = object : LinkedHashMap<String, Entry>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?) = size > 1000
    }
    @Volatile private var serverAddr: InetAddress? = null

    fun handle(p: IpPacket) {
        val len = p.udpPayloadLen
        if (len < 12) return
        val query = p.buf.copyOfRange(p.udpPayloadOff, p.udpPayloadOff + len)
        val src = p.src; val sport = p.srcPort; val dst = p.dst; val dport = p.dstPort
        try {
            engine.executor.execute {
                val resp = runCatching { resolve(query) }
                    .onFailure { engine.log("DNS: ${it.message}") }
                    .getOrNull() ?: return@execute
                engine.writeTun(PacketBuilder.udp(dst, dport, src, sport, resp))
            }
        } catch (_: Exception) { }
    }

    private fun resolve(query: ByteArray): ByteArray {
        val key = String(query, 2, query.size - 2, Charsets.ISO_8859_1)
        val now = System.currentTimeMillis()
        synchronized(cache) {
            cache[key]?.let { e ->
                if (e.expires > now) {
                    val r = e.data.copyOf()
                    r[0] = query[0]; r[1] = query[1]
                    return r
                }
                cache.remove(key)
            }
        }
        val server = serverAddr ?: InetAddress.getByName(s.server).also { serverAddr = it }
        val resp = if (s.viaProxy) viaTcp(server, query) else viaUdp(server, query)
        val rcode = resp.getOrNull(3)?.toInt()?.and(0xF) ?: 2
        if (resp.size >= 12 && rcode == 0) {
            synchronized(cache) { cache[key] = Entry(resp, now + 60_000) }
        }
        return resp
    }

    /** Пул открытых DNS-over-TCP соединений через прокси: экономит рукопожатие на каждый запрос. */
    private class PooledConn(val sock: java.net.Socket, var lastUsed: Long)
    private val pool = ArrayDeque<PooledConn>()

    private fun viaTcp(server: InetAddress, query: ByteArray): ByteArray {
        // Сначала пробуем переиспользовать соединение; если сервер его уже закрыл — открываем новое.
        val reused = synchronized(pool) {
            val now = System.currentTimeMillis()
            while (pool.isNotEmpty() && now - pool.first().lastUsed > IDLE_MS) runCatching { pool.removeFirst().sock.close() }
            pool.removeLastOrNull()
        }
        if (reused != null) {
            runCatching { return exchange(reused, query) }
            runCatching { reused.sock.close() }
        }
        val c = PooledConn(engine.connector.connect(server.address, null, 53, 8000), 0)
        try {
            return exchange(c, query)
        } catch (e: Exception) {
            runCatching { c.sock.close() }
            throw e
        }
    }

    private fun exchange(c: PooledConn, query: ByteArray): ByteArray {
        val sock = c.sock
        sock.soTimeout = 6000
        val out = sock.getOutputStream()
        out.write(byteArrayOf((query.size ushr 8).toByte(), query.size.toByte()) + query)
        out.flush()
        val inp = DataInputStream(sock.getInputStream())
        val n = inp.readUnsignedShort()
        val b = ByteArray(n)
        inp.readFully(b)
        c.lastUsed = System.currentTimeMillis()
        synchronized(pool) {
            if (pool.size < 4) pool.addLast(c) else runCatching { sock.close() }
        }
        return b
    }

    fun close() = synchronized(pool) { while (pool.isNotEmpty()) runCatching { pool.removeFirst().sock.close() } }

    companion object { private const val IDLE_MS = 20_000L }

    private fun viaUdp(server: InetAddress, query: ByteArray): ByteArray {
        DatagramSocket().use { ds ->
            s.protectUdp(ds)
            ds.soTimeout = 5000
            ds.send(DatagramPacket(query, query.size, InetSocketAddress(server, 53)))
            val b = ByteArray(4096)
            val pkt = DatagramPacket(b, b.size)
            ds.receive(pkt)
            return b.copyOf(pkt.length)
        }
    }
}
