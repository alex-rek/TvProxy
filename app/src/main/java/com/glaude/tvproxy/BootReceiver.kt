package com.glaude.tvproxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/** Автозапуск после загрузки ТВ (если включён и разрешение на VPN уже выдано). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val cfg = Config.load(ctx)
        if (!cfg.autostart || cfg.host.isBlank()) return
        if (VpnService.prepare(ctx) != null) return
        ProxyVpnService.start(ctx)
    }
}
