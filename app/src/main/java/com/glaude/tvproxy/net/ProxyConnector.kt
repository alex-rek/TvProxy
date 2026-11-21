package com.glaude.tvproxy.net

import android.util.Base64
import com.glaude.tvproxy.Config
import com.glaude.tvproxy.ProxyType
import java.io.IOException
import java.io.InputStream
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/** Открывает TCP-туннель до цели через HTTP CONNECT или SOCKS5 (с авторизацией). */
class ProxyConnector(
    private val cfg: Config,
    private val protect: (Socket) -> Boolean = { true },
) {
    @Volatile private var proxyAddr: InetAddress? = null

    private fun resolveProxy(): InetAddress =
        proxyAddr ?: InetAddress.getByName(cfg.host).also { proxyAddr = it }

    /** host — либо IP-адрес (байты), либо доменное имя. */
    fun connect(dstIp: ByteArray?, dstHost: String?, port: Int, timeoutMs: Int = 10_000): Socket {
        val s = Socket()
        try {
            protect(s)
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(resolveProxy(), cfg.port), timeoutMs)
            s.soTimeout = timeoutMs
            when (cfg.type) {
                ProxyType.SOCKS5 -> socks5(s, dstIp, dstHost, port)
                ProxyType.HTTP -> httpConnect(s, dstIp, dstHost, port)
            }
            s.soTimeout = 0
            return s
        } catch (e: Exception) {
            runCatching { s.close() }
            throw if (e is IOException) e else IOException(e.message, e)
        }
    }

    /** Результат UDP ASSOCIATE: управляющее TCP-соединение (держать открытым!) и адрес UDP-реле. */
    class UdpAssociation(val control: Socket, val relay: InetSocketAddress)

    /** SOCKS5 UDP ASSOCIATE (RFC 1928, п. 7). Только для SOCKS5. */
    fun udpAssociate(timeoutMs: Int = 10_000): UdpAssociation {
        if (cfg.type != ProxyType.SOCKS5) throw IOException("UDP поддерживается только для SOCKS5")
        val s = Socket()
        try {
            protect(s)
            val proxy = resolveProxy()
            s.connect(InetSocketAddress(proxy, cfg.port), timeoutMs)
            s.soTimeout = timeoutMs
            socks5Auth(s)
            // DST.ADDR = 0.0.0.0:0 — клиент заранее не знает, с какого адреса будет слать.
            s.getOutputStream().apply { write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)); flush() }
            val inp = s.getInputStream()
            val head = readN(inp, 4)
            val rep = head[1].toInt()
            if (rep != 0) throw IOException("SOCKS5 UDP: ${if (rep == 7) "сервер не поддерживает UDP" else socksErr(rep)}")
            val addr: InetAddress? = when (head[3].toInt()) {
                1 -> InetAddress.getByAddress(readN(inp, 4))
                4 -> InetAddress.getByAddress(readN(inp, 16))
                3 -> runCatching { InetAddress.getByName(String(readN(inp, inp.read() and 0xFF))) }.getOrNull()
                else -> throw IOException("SOCKS5 UDP: неверный ответ")
            }
            val p = readN(inp, 2)
            val port = ((p[0].toInt() and 0xFF) shl 8) or (p[1].toInt() and 0xFF)
            // Сервер часто отвечает 0.0.0.0 — тогда реле на том же адресе, что и прокси.
            val relayAddr = if (addr == null || addr.isAnyLocalAddress) proxy else addr
            s.soTimeout = 0
            return UdpAssociation(s, InetSocketAddress(relayAddr, port))
        } catch (e: Exception) {
            runCatching { s.close() }
            throw if (e is IOException) e else IOException(e.message, e)
        }
    }

    private fun socks5(s: Socket, ip: ByteArray?, host: String?, port: Int) {
        socks5Auth(s)
        socks5Connect(s, ip, host, port)
    }

    private fun socks5Auth(s: Socket) {
        val out = s.getOutputStream()
        val inp = s.getInputStream()
        if (cfg.hasAuth) out.write(byteArrayOf(5, 2, 0, 2)) else out.write(byteArrayOf(5, 1, 0))
        out.flush()
        val greet = readN(inp, 2)
        if (greet[0].toInt() != 5) throw IOException("Не SOCKS5 сервер")
        when (greet[1].toInt() and 0xFF) {
            0 -> {}
            2 -> {
                val u = cfg.user.toByteArray(); val p = cfg.pass.toByteArray()
                if (u.size > 255 || p.size > 255) throw IOException("Слишком длинный логин/пароль")
                val req = ByteArray(3 + u.size + p.size)
                req[0] = 1; req[1] = u.size.toByte()
                System.arraycopy(u, 0, req, 2, u.size)
                req[2 + u.size] = p.size.toByte()
                System.arraycopy(p, 0, req, 3 + u.size, p.size)
                out.write(req); out.flush()
                val r = readN(inp, 2)
                if (r[1].toInt() != 0) throw IOException("SOCKS5: неверный логин или пароль")
            }
            0xFF -> throw IOException(if (cfg.hasAuth) "SOCKS5: метод авторизации отклонён" else "SOCKS5: сервер требует логин и пароль")
            else -> throw IOException("SOCKS5: неподдерживаемый метод авторизации")
        }
    }

    private fun socks5Connect(s: Socket, ip: ByteArray?, host: String?, port: Int) {
        val out = s.getOutputStream()
        val inp = s.getInputStream()
        val addr: ByteArray = when {
            ip != null && ip.size == 4 -> byteArrayOf(1) + ip
            ip != null -> byteArrayOf(4) + ip
            else -> { val h = host!!.toByteArray(); byteArrayOf(3, h.size.toByte()) + h }
        }
        out.write(byteArrayOf(5, 1, 0) + addr + byteArrayOf((port ushr 8).toByte(), port.toByte()))
        out.flush()
        val head = readN(inp, 4)
        val rep = head[1].toInt()
        if (rep != 0) throw IOException("SOCKS5: ошибка подключения (${socksErr(rep)})")
        when (head[3].toInt()) {
            1 -> readN(inp, 4 + 2)
            4 -> readN(inp, 16 + 2)
            3 -> readN(inp, (inp.read() and 0xFF) + 2)
            else -> throw IOException("SOCKS5: неверный ответ")
        }
    }

    private fun socksErr(c: Int) = when (c) {
        1 -> "общий сбой"; 2 -> "запрещено правилами"; 3 -> "сеть недоступна"; 4 -> "хост недоступен"
        5 -> "соединение отклонено"; 6 -> "TTL истёк"; 7 -> "команда не поддерживается"; 8 -> "тип адреса не поддерживается"
        else -> "код $c"
    }

    private fun httpConnect(s: Socket, ip: ByteArray?, host: String?, port: Int) {
        val target = when {
            ip != null -> {
                val a = InetAddress.getByAddress(ip)
                if (a is Inet6Address) "[${a.hostAddress!!.substringBefore('%')}]:$port" else "${a.hostAddress}:$port"
            }
            else -> "$host:$port"
        }
        val sb = StringBuilder()
            .append("CONNECT ").append(target).append(" HTTP/1.1\r\n")
            .append("Host: ").append(target).append("\r\n")
            .append("User-Agent: TvProxy/1.0\r\n")
            .append("Proxy-Connection: keep-alive\r\n")
        if (cfg.hasAuth) {
            val token = Base64.encodeToString("${cfg.user}:${cfg.pass}".toByteArray(), Base64.NO_WRAP)
            sb.append("Proxy-Authorization: Basic ").append(token).append("\r\n")
        }
        sb.append("\r\n")
        val out = s.getOutputStream()
        out.write(sb.toString().toByteArray()); out.flush()

        // Читаем заголовки ответа побайтно, чтобы не съесть данные туннеля.
        val inp = s.getInputStream()
        val head = StringBuilder()
        var state = 0
        while (state < 4) {
            val c = inp.read()
            if (c < 0) throw IOException("HTTP-прокси закрыл соединение")
            head.append(c.toChar())
            if (head.length > 16384) throw IOException("HTTP-прокси: слишком длинный ответ")
            state = when {
                c == '\r'.code && (state == 0 || state == 2) -> state + 1
                c == '\n'.code && (state == 1 || state == 3) -> state + 1
                c == '\r'.code -> 1
                else -> 0
            }
        }
        val status = head.lineSequence().first()
        val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
        if (code !in 200..299) {
            throw IOException(when (code) {
                407 -> "HTTP-прокси: требуется авторизация (407)"
                403 -> "HTTP-прокси: доступ запрещён (403)"
                else -> "HTTP-прокси: ${status.trim()}"
            })
        }
    }

    companion object {
        fun readN(inp: InputStream, n: Int): ByteArray {
            val b = ByteArray(n)
            var o = 0
            while (o < n) {
                val r = inp.read(b, o, n - o)
                if (r < 0) throw IOException("Соединение с прокси закрыто")
                o += r
            }
            return b
        }
    }
}
