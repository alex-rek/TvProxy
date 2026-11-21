package com.glaude.tvproxy.ui

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.glaude.tvproxy.AppMode
import com.glaude.tvproxy.Config
import com.glaude.tvproxy.ProxyVpnService
import com.glaude.tvproxy.R
import com.glaude.tvproxy.VpnState

class AppsActivity : AppCompatActivity() {

    private class AppItem(val pkg: String, val label: String, val system: Boolean, val launchable: Boolean) {
        var icon: Drawable? = null
    }

    private val selected = mutableSetOf<String>()
    private var all: List<AppItem> = emptyList()
    private var shown: List<AppItem> = emptyList()
    private lateinit var adapter: Adapter
    private lateinit var hint: TextView
    private lateinit var title: TextView
    private lateinit var search: EditText
    private lateinit var showSystem: CheckBox
    private lateinit var mode: AppMode
    private var initial: Set<String> = emptySet()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_apps)
        val cfg = Config.load(this)
        mode = cfg.appMode
        initial = cfg.apps
        selected += cfg.apps

        title = findViewById(R.id.title)
        hint = findViewById(R.id.hint)
        search = findViewById(R.id.search)
        showSystem = findViewById(R.id.showSystem)
        val list = findViewById<RecyclerView>(R.id.list)
        adapter = Adapter()
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter

        findViewById<Button>(R.id.btnDone).setOnClickListener { finish() }
        showSystem.setOnCheckedChangeListener { _, _ -> applyFilter() }
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) = applyFilter()
        })
        renderTitle()
        hint.text = "Загрузка списка приложений…"

        // Две фазы: сначала обычные (запускаемые) приложения — быстро, затем системные службы.
        Thread {
            val pkgs = queryPackages()
            val first = buildItems(pkgs.filter { it.first in launchable || it.first in selected })
            runOnUiThread {
                all = first
                applyFilter()
                list.post { list.getChildAt(0)?.requestFocus() }
            }
            val rest = buildItems(pkgs.filter { it.first !in launchable && it.first !in selected })
            runOnUiThread {
                all = (first + rest).sortedWith(order())
                applyFilter()
            }
        }.start()
    }

    override fun onPause() {
        super.onPause()
        val cfg = Config.load(this)
        Config.save(this, cfg.copy(apps = selected.toSet()))
    }

    override fun finish() {
        // Если VPN уже работает — перезапускаем с новым списком.
        if (selected != initial && VpnState.status == VpnState.Status.RUNNING) {
            Config.save(this, Config.load(this).copy(apps = selected.toSet()))
            ProxyVpnService.start(this)
        }
        super.finish()
    }

    private fun renderTitle() {
        title.text = if (mode == AppMode.ONLY_SELECTED) "Через прокси: ${selected.size}" else "Исключены из прокси: ${selected.size}"
    }

    private val launchable = HashSet<String>()

    /** Пакеты с разрешением INTERNET (без загрузки названий — это медленно). */
    private fun queryPackages(): List<Pair<String, ApplicationInfo>> {
        val pm = packageManager
        for (cat in listOf(Intent.CATEGORY_LEANBACK_LAUNCHER, Intent.CATEGORY_LAUNCHER)) {
            val i = Intent(Intent.ACTION_MAIN).addCategory(cat)
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(i, 0).forEach { launchable += it.activityInfo.packageName }
        }
        @Suppress("DEPRECATION")
        return pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            .filter { it.packageName != packageName }
            .filter { p -> p.requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true }
            .mapNotNull { p -> p.applicationInfo?.let { p.packageName to it } }
    }

    private fun buildItems(pkgs: List<Pair<String, ApplicationInfo>>): List<AppItem> {
        val pm = packageManager
        return pkgs.map { (pkg, ai) ->
            val sys = ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            AppItem(pkg, runCatching { ai.loadLabel(pm).toString() }.getOrDefault(pkg), sys, pkg in launchable)
        }.sortedWith(order())
    }

    private fun order() = compareBy<AppItem>({ it.pkg !in selected }, { !it.launchable }, { it.label.lowercase() })

    private fun applyFilter() {
        val q = search.text.toString().trim().lowercase()
        val sys = showSystem.isChecked
        shown = all.filter { a ->
            (sys || a.launchable || a.pkg in selected) &&
                (q.isEmpty() || a.label.lowercase().contains(q) || a.pkg.lowercase().contains(q))
        }
        hint.text = (if (mode == AppMode.ONLY_SELECTED)
            "Отмеченные приложения будут ходить через прокси, остальные — напрямую."
        else
            "Все приложения идут через прокси, кроме отмеченных.") +
            "  Показано: ${shown.size}" + (if (!sys) " (включите «Системные», чтобы увидеть службы)" else "")
        adapter.notifyDataSetChanged()
    }

    private inner class Holder(v: View) : RecyclerView.ViewHolder(v) {
        val icon: ImageView = v.findViewById(R.id.icon)
        val label: TextView = v.findViewById(R.id.label)
        val pkg: TextView = v.findViewById(R.id.pkg)
        val check: CheckBox = v.findViewById(R.id.check)
    }

    private inner class Adapter : RecyclerView.Adapter<Holder>() {
        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false))

        override fun getItemCount() = shown.size

        override fun onBindViewHolder(h: Holder, position: Int) {
            val a = shown[position]
            h.label.text = a.label
            h.pkg.text = a.pkg
            h.check.isChecked = a.pkg in selected
            if (a.icon == null) a.icon = runCatching { packageManager.getApplicationIcon(a.pkg) }.getOrNull()
            h.icon.setImageDrawable(a.icon)
            h.itemView.setOnClickListener {
                if (!selected.remove(a.pkg)) selected += a.pkg
                h.check.isChecked = a.pkg in selected
                renderTitle()
            }
        }
    }
}
