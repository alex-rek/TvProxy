package com.glaude.tvproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import com.glaude.tvproxy.net.DnsForwarder
import com.glaude.tvproxy.net.ProxyConnector
import com.glaude.tvproxy.net.TunEngine
import com.glaude.tvproxy.ui.MainActivity

/** Глобальное состояние для UI. */
object VpnState {
    enum class Status { STOPPED, STARTING, RUNNING, ERROR }

    @Volatile var status = Status.STOPPED; private set
    @Volatile var message = ""; private set
    private val main = Handler(Looper.getMainLooper())
    private val listeners = mutableSetOf<() -> Unit>()

    fun set(s: Status, msg: String = "") {
        status = s; message = msg
        main.post { listeners.toList().forEach { it() } }
    }

    fun listen(l: () -> Unit) { listeners += l }
    fun unlisten(l: () -> Unit) { listeners -= l }
}

class ProxyVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var engine: TunEngine? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopVpn(); return START_NOT_STICKY }
        goForeground()
        Thread { startVpn() }.start()
        return START_STICKY
    }

    private fun goForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.app_name), NotificationManager.IMPORTANCE_LOW))
        }
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        @Suppress("DEPRECATION")
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL) else Notification.Builder(this)
        val n = b.setSmallIcon(R.drawable.ic_stat)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notif_running))
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(1, n)
    }

    @Synchronized
    private fun startVpn() {
        stopEngine()
        val cfg = Config.load(this)
        VpnState.set(VpnState.Status.STARTING)
        if (cfg.host.isBlank()) return fail("Не указан адрес прокси")
        if (cfg.appMode == AppMode.ONLY_SELECTED && cfg.apps.isEmpty()) return fail("Не выбрано ни одного приложения")

        val b = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(MTU)
            .addAddress(TUN_V4, 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(DNS_V4)
            .setBlocking(true)
        runCatching { b.addAddress(TUN_V6, 64); b.addRoute("::", 0) }
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)

        val pm = packageManager
        var added = 0
        try {
            when (cfg.appMode) {
                AppMode.ONLY_SELECTED -> for (pkg in cfg.apps) {
                    if (pkg == packageName) continue
                    try { b.addAllowedApplication(pkg); added++ } catch (_: PackageManager.NameNotFoundException) {}
                }
                AppMode.ALL_EXCEPT_SELECTED -> {
                    b.addDisallowedApplication(packageName)
                    for (pkg in cfg.apps) try { b.addDisallowedApplication(pkg) } catch (_: PackageManager.NameNotFoundException) {}
                }
            }
        } catch (e: Exception) { return fail("Ошибка настройки приложений: ${e.message}") }
        if (cfg.appMode == AppMode.ONLY_SELECTED && added == 0) return fail("Выбранные приложения не установлены")

        val fd = try { b.establish() } catch (e: Exception) { return fail("Не удалось создать VPN: ${e.message}") }
            ?: return fail("Нет разрешения на VPN — откройте приложение")
        tun = fd

        val connector = ProxyConnector(cfg) { protect(it) }
        val dns = DnsForwarder.Settings(cfg.dnsServer.ifBlank { "1.1.1.1" }, cfg.dnsViaProxy) { protect(it) }
        val what = if (cfg.appMode == AppMode.ONLY_SELECTED) "приложений: $added" else "все, кроме ${cfg.apps.size}"
        val base = "${cfg.type.name} ${cfg.host}:${cfg.port} · $what" +
            if (cfg.type == ProxyType.SOCKS5 && cfg.udpViaSocks) " · UDP" else ""
        var lastErr = 0L
        val udp = cfg.type == ProxyType.SOCKS5 && cfg.udpViaSocks
        engine = TunEngine(fd, connector, dns, udp) { msg ->
            // Показываем в интерфейсе последнюю ошибку прокси (не чаще раза в 2 с).
            val now = System.currentTimeMillis()
            if (now - lastErr > 2000 && VpnState.status == VpnState.Status.RUNNING) {
                lastErr = now
                VpnState.set(VpnState.Status.RUNNING, "$base\nПоследняя ошибка: ${msg.substringAfter(" — ")}")
            }
        }.also { it.start() }
        VpnState.set(VpnState.Status.RUNNING, base)
    }

    private fun fail(msg: String) {
        stopEngine()
        VpnState.set(VpnState.Status.ERROR, msg)
        stopForegroundCompat()
        stopSelf()
    }

    private fun stopEngine() {
        engine?.stop(); engine = null
        runCatching { tun?.close() }; tun = null
    }

    private fun stopVpn() {
        stopEngine()
        VpnState.set(VpnState.Status.STOPPED)
        stopForegroundCompat()
        stopSelf()
    }

    @Suppress("DEPRECATION")
    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else stopForeground(true)
    }

    override fun onRevoke() { stopVpn() }

    override fun onDestroy() {
        stopEngine()
        if (VpnState.status == VpnState.Status.RUNNING || VpnState.status == VpnState.Status.STARTING)
            VpnState.set(VpnState.Status.STOPPED)
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "com.glaude.tvproxy.STOP"
        private const val CHANNEL = "vpn"
        private const val MTU = 1500
        private const val TUN_V4 = "10.111.0.1"
        private const val DNS_V4 = "10.111.0.2"
        private const val TUN_V6 = "fd11:1:1::1"

        fun start(ctx: Context) {
            val i = Intent(ctx, ProxyVpnService::class.java)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, ProxyVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}
