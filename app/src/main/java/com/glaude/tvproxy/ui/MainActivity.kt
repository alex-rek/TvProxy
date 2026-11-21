package com.glaude.tvproxy.ui

import android.content.Intent
import android.content.res.ColorStateList
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.RadioButton
import android.widget.TextView
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.glaude.tvproxy.AppMode
import com.glaude.tvproxy.Config
import com.glaude.tvproxy.ProxyType
import com.glaude.tvproxy.ProxyVpnService
import com.glaude.tvproxy.R
import com.glaude.tvproxy.VpnState
import com.glaude.tvproxy.net.ProxyConnector
import com.glaude.tvproxy.net.UdpRelay

class MainActivity : AppCompatActivity() {
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var user: EditText
    private lateinit var pass: EditText
    private lateinit var dns: EditText
    private lateinit var typeSocks: RadioButton
    private lateinit var typeHttp: RadioButton
    private lateinit var modeOnly: RadioButton
    private lateinit var modeExcept: RadioButton
    private lateinit var dnsViaProxy: CheckBox
    private lateinit var autostart: CheckBox
    private lateinit var udpViaSocks: CheckBox
    private lateinit var btnConnect: Button
    private lateinit var btnApps: Button
    private lateinit var btnTest: Button
    private lateinit var statusDot: View
    private lateinit var statusText: TextView
    private lateinit var statusMsg: TextView
    private lateinit var testResult: TextView

    private var apps: Set<String> = emptySet()
    private var testing = false
    private val stateListener = { renderState() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        host = findViewById(R.id.host); port = findViewById(R.id.port)
        user = findViewById(R.id.user); pass = findViewById(R.id.pass)
        dns = findViewById(R.id.dns)
        typeSocks = findViewById(R.id.typeSocks); typeHttp = findViewById(R.id.typeHttp)
        modeOnly = findViewById(R.id.modeOnly); modeExcept = findViewById(R.id.modeExcept)
        dnsViaProxy = findViewById(R.id.dnsViaProxy); autostart = findViewById(R.id.autostart)
        udpViaSocks = findViewById(R.id.udpViaSocks)
        btnConnect = findViewById(R.id.btnConnect); btnApps = findViewById(R.id.btnApps); btnTest = findViewById(R.id.btnTest)
        statusDot = findViewById(R.id.statusDot); statusText = findViewById(R.id.statusText)
        statusMsg = findViewById(R.id.statusMsg); testResult = findViewById(R.id.testResult)

        fill(Config.load(this))

        // Подставляем стандартный порт при смене типа, если поле пустое или стандартное.
        typeSocks.setOnCheckedChangeListener { _, on ->
            if (on && port.text.toString() in listOf("", "8080", "3128")) port.setText("1080")
            udpViaSocks.isEnabled = on
        }
        typeHttp.setOnCheckedChangeListener { _, on -> if (on && port.text.toString() in listOf("", "1080")) port.setText("8080") }
        modeOnly.setOnCheckedChangeListener { _, _ -> renderApps() }

        btnConnect.setOnClickListener { toggle() }
        btnApps.setOnClickListener {
            save()
            startActivity(Intent(this, AppsActivity::class.java))
        }
        btnTest.setOnClickListener { testProxy() }
        btnConnect.requestFocus()
    }

    override fun onResume() {
        super.onResume()
        apps = Config.load(this).apps
        renderApps()
        VpnState.listen(stateListener)
        renderState()
    }

    override fun onPause() {
        super.onPause()
        VpnState.unlisten(stateListener)
        save()
    }

    private fun fill(c: Config) {
        (if (c.type == ProxyType.HTTP) typeHttp else typeSocks).isChecked = true
        host.setText(c.host)
        port.setText(c.port.toString())
        user.setText(c.user)
        pass.setText(c.pass)
        dns.setText(c.dnsServer)
        dnsViaProxy.isChecked = c.dnsViaProxy
        autostart.isChecked = c.autostart
        udpViaSocks.isChecked = c.udpViaSocks
        udpViaSocks.isEnabled = c.type == ProxyType.SOCKS5
        (if (c.appMode == AppMode.ALL_EXCEPT_SELECTED) modeExcept else modeOnly).isChecked = true
        apps = c.apps
    }

    private fun current(): Config = Config(
        type = if (typeHttp.isChecked) ProxyType.HTTP else ProxyType.SOCKS5,
        host = host.text.toString().trim(),
        port = port.text.toString().toIntOrNull()?.coerceIn(1, 65535) ?: if (typeHttp.isChecked) 8080 else 1080,
        user = user.text.toString(),
        pass = pass.text.toString(),
        dnsServer = dns.text.toString().trim().ifEmpty { "1.1.1.1" },
        dnsViaProxy = dnsViaProxy.isChecked,
        appMode = if (modeExcept.isChecked) AppMode.ALL_EXCEPT_SELECTED else AppMode.ONLY_SELECTED,
        apps = Config.load(this).apps,
        autostart = autostart.isChecked,
        udpViaSocks = udpViaSocks.isChecked,
    )

    private fun save(): Config = current().also { Config.save(this, it) }

    private fun renderApps() {
        val n = apps.size
        btnApps.text = when {
            modeOnly.isChecked && n == 0 -> "Выбрать приложения…"
            modeOnly.isChecked -> "Через прокси: $n — изменить"
            n == 0 -> "Исключить приложения…"
            else -> "Исключено: $n — изменить"
        }
    }

    private fun renderState() {
        val (label, color) = when (VpnState.status) {
            VpnState.Status.RUNNING -> "Подключено" to R.color.ok
            VpnState.Status.STARTING -> "Подключение…" to R.color.warn
            VpnState.Status.ERROR -> "Ошибка" to R.color.err
            VpnState.Status.STOPPED -> "Отключено" to R.color.muted
        }
        statusText.text = label
        statusDot.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(this, color))
        statusMsg.text = VpnState.message
        val active = VpnState.status == VpnState.Status.RUNNING || VpnState.status == VpnState.Status.STARTING
        btnConnect.text = if (active) "Отключить" else "Подключить"
    }

    private fun toggle() {
        val active = VpnState.status == VpnState.Status.RUNNING || VpnState.status == VpnState.Status.STARTING
        if (active) { ProxyVpnService.stop(this); return }
        val c = save()
        if (c.host.isEmpty()) { host.requestFocus(); testResult.text = "Укажите адрес прокси-сервера"; return }
        if (c.appMode == AppMode.ONLY_SELECTED && c.apps.isEmpty()) {
            testResult.text = "Выберите приложения, которые пойдут через прокси"
            btnApps.requestFocus(); return
        }
        val prep = VpnService.prepare(this)
        if (prep != null) {
            try { startActivityForResult(prep, REQ_VPN) } catch (e: Exception) {
                testResult.text = "Система не поддерживает VPN: ${e.message}"
            }
        } else startVpn()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) startVpn() else testResult.text = "Разрешение на VPN не выдано"
        }
    }

    private fun startVpn() {
        VpnState.set(VpnState.Status.STARTING)
        ProxyVpnService.start(this)
    }

    /** Подключаемся через прокси к api.ipify.org и показываем внешний IP. */
    private fun testProxy() {
        val c = save()
        if (c.host.isEmpty()) { testResult.text = "Укажите адрес прокси-сервера"; return }
        testResult.setTextColor(ContextCompat.getColor(this, R.color.muted))
        if (testing) return
        testing = true
        testResult.text = "Проверка…"
        Thread {
            val t0 = System.currentTimeMillis()
            val res = runCatching {
                ProxyConnector(c).connect(null, "api.ipify.org", 80, 10_000).use { s ->
                    s.soTimeout = 10_000
                    s.getOutputStream().write(
                        "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: TvProxy\r\nConnection: close\r\n\r\n".toByteArray())
                    val body = s.getInputStream().readBytes().toString(Charsets.UTF_8)
                    val code = body.lineSequence().first().split(' ').getOrNull(1)
                    if (code != "200") throw Exception("ответ сервера: ${body.lineSequence().first()}")
                    body.substringAfter("\r\n\r\n").trim()
                }
            }
            val ms = System.currentTimeMillis() - t0
            // UDP проверяем только если TCP работает и выбран SOCKS5 с UDP.
            val udp: Result<Long>? = if (res.isSuccess && c.type == ProxyType.SOCKS5 && c.udpViaSocks)
                runCatching { UdpRelay.selfTest(ProxyConnector(c)) } else null
            runOnUiThread {
                testing = false
                res.onSuccess {
                    testResult.setTextColor(ContextCompat.getColor(this, R.color.ok))
                    val udpLine = when {
                        udp == null -> ""
                        udp.isSuccess -> "\nUDP: работает · ${udp.getOrNull()} мс"
                        else -> "\nUDP: не работает — ${udp.exceptionOrNull()?.message}"
                    }
                    testResult.text = "Прокси работает · внешний IP: $it · $ms мс$udpLine"
                    if (udp?.isFailure == true) testResult.setTextColor(ContextCompat.getColor(this, R.color.warn))
                }.onFailure {
                    testResult.setTextColor(ContextCompat.getColor(this, R.color.err))
                    testResult.text = "Не работает: ${it.message ?: it.javaClass.simpleName}"
                }
            }
        }.start()
    }

    companion object { private const val REQ_VPN = 1 }
}
