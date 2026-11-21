package com.glaude.tvproxy

import android.content.Context

enum class ProxyType { HTTP, SOCKS5 }

/** Какие приложения заворачивать в прокси. */
enum class AppMode { ONLY_SELECTED, ALL_EXCEPT_SELECTED }

data class Config(
    val type: ProxyType = ProxyType.SOCKS5,
    val host: String = "",
    val port: Int = 1080,
    val user: String = "",
    val pass: String = "",
    val dnsServer: String = "1.1.1.1",
    val dnsViaProxy: Boolean = true,
    val appMode: AppMode = AppMode.ONLY_SELECTED,
    val apps: Set<String> = emptySet(),
    val autostart: Boolean = false,
    val udpViaSocks: Boolean = true,
) {
    val hasAuth get() = user.isNotEmpty()

    companion object {
        private const val PREFS = "config"

        fun load(ctx: Context): Config {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            return Config(
                type = runCatching { ProxyType.valueOf(p.getString("type", null)!!) }.getOrDefault(ProxyType.SOCKS5),
                host = p.getString("host", "")!!,
                port = p.getInt("port", 1080),
                user = p.getString("user", "")!!,
                pass = p.getString("pass", "")!!,
                dnsServer = p.getString("dns", "1.1.1.1")!!,
                dnsViaProxy = p.getBoolean("dnsViaProxy", true),
                appMode = runCatching { AppMode.valueOf(p.getString("appMode", null)!!) }.getOrDefault(AppMode.ONLY_SELECTED),
                apps = p.getStringSet("apps", emptySet())!!.toSet(),
                autostart = p.getBoolean("autostart", false),
                udpViaSocks = p.getBoolean("udp", true),
            )
        }

        fun save(ctx: Context, c: Config) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("type", c.type.name)
                .putString("host", c.host)
                .putInt("port", c.port)
                .putString("user", c.user)
                .putString("pass", c.pass)
                .putString("dns", c.dnsServer)
                .putBoolean("dnsViaProxy", c.dnsViaProxy)
                .putString("appMode", c.appMode.name)
                .putStringSet("apps", c.apps)
                .putBoolean("autostart", c.autostart)
                .putBoolean("udp", c.udpViaSocks)
                .apply()
        }
    }
}
