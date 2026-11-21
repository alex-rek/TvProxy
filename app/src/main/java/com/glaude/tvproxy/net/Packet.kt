package com.glaude.tvproxy.net

/**
 * Разбор и сборка IPv4/IPv6 + TCP/UDP пакетов для TUN-интерфейса.
 * Все числа в сети big-endian.
 */
object Proto {
    const val TCP = 6
    const val UDP = 17

    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

class IpPacket(val buf: ByteArray, val len: Int) {
    val version = (buf[0].toInt() ushr 4) and 0xF
    var proto = -1; private set
    var ipHeaderLen = 0; private set
    lateinit var src: ByteArray; private set
    lateinit var dst: ByteArray; private set
    var l4Len = 0; private set   // длина L4 (заголовок + данные)

    val l4Off get() = ipHeaderLen

    /** false — пакет не поддерживается (фрагмент, ext-заголовки IPv6 и т.п.). */
    fun parse(): Boolean {
        if (version == 4) {
            if (len < 20) return false
            ipHeaderLen = (buf[0].toInt() and 0xF) * 4
            val total = u16(buf, 2)
            if (total > len || total < ipHeaderLen) return false
            val flagsFrag = u16(buf, 6)
            if (flagsFrag and 0x3FFF != 0) return false // фрагменты не поддерживаем
            proto = buf[9].toInt() and 0xFF
            src = buf.copyOfRange(12, 16)
            dst = buf.copyOfRange(16, 20)
            l4Len = total - ipHeaderLen
            return true
        } else if (version == 6) {
            if (len < 40) return false
            ipHeaderLen = 40
            proto = buf[6].toInt() and 0xFF
            val payload = u16(buf, 4)
            if (40 + payload > len) return false
            src = buf.copyOfRange(8, 24)
            dst = buf.copyOfRange(24, 40)
            l4Len = payload
            return true
        }
        return false
    }

    // ---- TCP ----
    val srcPort get() = u16(buf, l4Off)
    val dstPort get() = u16(buf, l4Off + 2)
    val tcpSeq get() = u32(buf, l4Off + 4)
    val tcpAck get() = u32(buf, l4Off + 8)
    val tcpHeaderLen get() = ((buf[l4Off + 12].toInt() ushr 4) and 0xF) * 4
    val tcpFlags get() = buf[l4Off + 13].toInt() and 0xFF
    val tcpWindow get() = u16(buf, l4Off + 14)
    val tcpPayloadOff get() = l4Off + tcpHeaderLen
    val tcpPayloadLen get() = l4Len - tcpHeaderLen

    /** Значение опции MSS из SYN, либо -1. */
    fun tcpMss(): Int {
        var i = l4Off + 20
        val end = l4Off + tcpHeaderLen
        while (i < end) {
            val kind = buf[i].toInt() and 0xFF
            if (kind == 0) break
            if (kind == 1) { i++; continue }
            if (i + 1 >= end) break
            val l = buf[i + 1].toInt() and 0xFF
            if (l < 2) break
            if (kind == 2 && l == 4) return u16(buf, i + 2)
            i += l
        }
        return -1
    }

    // ---- UDP ----
    val udpPayloadOff get() = l4Off + 8
    val udpPayloadLen get() = u16(buf, l4Off + 4) - 8

    companion object {
        fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
        fun u32(b: ByteArray, o: Int) =
            ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
                ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)
    }
}

object PacketBuilder {
    private fun put16(b: ByteArray, o: Int, v: Int) { b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte() }
    private fun put32(b: ByteArray, o: Int, v: Int) {
        b[o] = (v ushr 24).toByte(); b[o + 1] = (v ushr 16).toByte(); b[o + 2] = (v ushr 8).toByte(); b[o + 3] = v.toByte()
    }

    private fun sum(b: ByteArray, off: Int, len: Int, init: Long = 0): Long {
        var s = init
        var i = off
        val end = off + len
        while (i + 1 < end) { s += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF); i += 2 }
        if (i < end) s += (b[i].toInt() and 0xFF) shl 8
        return s
    }

    private fun fold(s0: Long): Int {
        var s = s0
        while (s ushr 16 != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return (s.inv() and 0xFFFF).toInt()
    }

    /** Пишет IP-заголовок, возвращает его длину. */
    private fun ipHeader(p: ByteArray, src: ByteArray, dst: ByteArray, proto: Int, l4Len: Int): Int {
        return if (src.size == 4) {
            p[0] = 0x45; p[1] = 0
            put16(p, 2, 20 + l4Len)
            put16(p, 4, 0); put16(p, 6, 0x4000) // DF
            p[8] = 64; p[9] = proto.toByte()
            put16(p, 10, 0)
            System.arraycopy(src, 0, p, 12, 4)
            System.arraycopy(dst, 0, p, 16, 4)
            put16(p, 10, fold(sum(p, 0, 20)))
            20
        } else {
            p[0] = 0x60; p[1] = 0; p[2] = 0; p[3] = 0
            put16(p, 4, l4Len)
            p[6] = proto.toByte(); p[7] = 64
            System.arraycopy(src, 0, p, 8, 16)
            System.arraycopy(dst, 0, p, 24, 16)
            40
        }
    }

    private fun pseudoSum(src: ByteArray, dst: ByteArray, proto: Int, l4Len: Int): Long {
        var s = sum(src, 0, src.size) + sum(dst, 0, dst.size)
        s += proto.toLong()
        s += l4Len.toLong()
        return s
    }

    fun tcp(
        src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int,
        seq: Int, ack: Int, flags: Int, window: Int,
        data: ByteArray? = null, dataOff: Int = 0, dataLen: Int = 0,
        mss: Int = -1,
    ): ByteArray {
        val optLen = if (mss > 0) 4 else 0
        val tcpLen = 20 + optLen + dataLen
        val ipLen = if (src.size == 4) 20 else 40
        val p = ByteArray(ipLen + tcpLen)
        ipHeader(p, src, dst, Proto.TCP, tcpLen)
        val t = ipLen
        put16(p, t, srcPort); put16(p, t + 2, dstPort)
        put32(p, t + 4, seq); put32(p, t + 8, ack)
        p[t + 12] = (((20 + optLen) / 4) shl 4).toByte()
        p[t + 13] = flags.toByte()
        put16(p, t + 14, window)
        if (mss > 0) { p[t + 20] = 2; p[t + 21] = 4; put16(p, t + 22, mss) }
        if (dataLen > 0) System.arraycopy(data!!, dataOff, p, t + 20 + optLen, dataLen)
        put16(p, t + 16, fold(sum(p, t, tcpLen, pseudoSum(src, dst, Proto.TCP, tcpLen))))
        return p
    }

    fun udp(src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int, data: ByteArray, dataLen: Int = data.size): ByteArray {
        val udpLen = 8 + dataLen
        val ipLen = if (src.size == 4) 20 else 40
        val p = ByteArray(ipLen + udpLen)
        ipHeader(p, src, dst, Proto.UDP, udpLen)
        val u = ipLen
        put16(p, u, srcPort); put16(p, u + 2, dstPort); put16(p, u + 4, udpLen)
        System.arraycopy(data, 0, p, u + 8, dataLen)
        var c = fold(sum(p, u, udpLen, pseudoSum(src, dst, Proto.UDP, udpLen)))
        if (c == 0) c = 0xFFFF
        put16(p, u + 6, c)
        return p
    }
}
