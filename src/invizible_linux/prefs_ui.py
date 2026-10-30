from __future__ import annotations

from typing import Any, Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk

from .config import save_settings
from .confgen import sync_autostart

SaveFn = Callable[[], None]


def _bool(settings: dict[str, Any], key: str) -> bool:
    return bool(settings.get(key))


def switch_row(settings: dict[str, Any], key: str, title: str, subtitle: str, on_save: SaveFn) -> Adw.SwitchRow:
    row = Adw.SwitchRow(title=title, subtitle=subtitle)
    row.set_active(_bool(settings, key))

    def changed(r: Adw.SwitchRow, *_args) -> None:
        settings[key] = r.get_active()
        if key.startswith("sw_autostart"):
            sync_autostart(settings)
        on_save()

    row.connect("notify::active", changed)
    return row


def entry_row(settings: dict[str, Any], key: str, title: str, on_save: SaveFn) -> Adw.EntryRow:
    row = Adw.EntryRow(title=title)
    row.set_text(str(settings.get(key) or ""))

    def changed(r: Adw.EntryRow, *_args) -> None:
        settings[key] = r.get_text()
        on_save()

    row.connect("changed", changed)
    return row


def combo_row(
    settings: dict[str, Any],
    key: str,
    title: str,
    subtitle: str,
    options: list[tuple[str, str]],
    on_save: SaveFn,
) -> Adw.ComboRow:
    model = Gtk.StringList.new([label for label, _value in options])
    row = Adw.ComboRow(title=title, subtitle=subtitle, model=model)
    current = str(settings.get(key) or options[0][1])
    for i, (_label, value) in enumerate(options):
        if value == current:
            row.set_selected(i)
            break

    def changed(r: Adw.ComboRow, *_args) -> None:
        idx = r.get_selected()
        if 0 <= idx < len(options):
            new_val = options[idx][1]
            if settings.get(key) == new_val:
                return
            settings[key] = new_val
            on_save()

    row.connect("notify::selected", changed)
    return row


def text_row(settings: dict[str, Any], key: str, title: str, subtitle: str, on_save: SaveFn) -> Adw.ExpanderRow:
    row = Adw.ExpanderRow(title=title, subtitle=subtitle)
    view = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR)
    view.set_monospace(True)
    view.get_buffer().set_text(str(settings.get(key) or ""))
    view.set_size_request(-1, 120)
    scroll = Gtk.ScrolledWindow(min_content_height=120, hexpand=True)
    scroll.set_child(view)
    row.add_row(scroll)

    def persist(*_args) -> None:
        buf = view.get_buffer()
        settings[key] = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        on_save()

    view.get_buffer().connect("changed", persist)
    return row


def build_pages(settings: dict[str, Any], on_change: SaveFn) -> list[Adw.PreferencesPage]:
    def save() -> None:
        save_settings(settings)
        on_change()

    s = settings
    pages: list[Adw.PreferencesPage] = []

    fast = Adw.PreferencesPage(title="Rápidos", icon_name="preferences-system-symbolic")
    profile = Adw.PreferencesGroup(title="Perfil de uso")

    def save_profile() -> None:
        from .profiles import apply_profile

        apply_profile(s, str(s.get("usage_profile") or "home"))
        save()

    profile.add(combo_row(s, "usage_profile", "Perfil", "Ajusta varios interruptores a la vez. Puedes retocarlos después.", [
        ("Casa (solo proxy local)", "home"),
        ("Censura (Snowflake / puentes)", "censorship"),
        ("Máximo aislamiento", "max"),
    ], save_profile))
    fast.add(profile)

    auto = Adw.PreferencesGroup(title="Inicio automático")
    auto.add(switch_row(s, "sw_autostart_dns", "Inicio automático de DNSCrypt", "Arranca DNSCrypt al iniciar sesión", save))
    auto.add(switch_row(s, "sw_autostart_tor", "Inicio automático de Tor", "Arranca Tor al iniciar sesión", save))
    auto.add(switch_row(s, "sw_autostart_itpd", "Arrancar I2P al inicio", "Arranca I2P al iniciar sesión", save))
    auto.add(entry_row(s, "autostart_delay", "Retraso (segundos)", save))
    fast.add(auto)

    dns = Adw.PreferencesGroup(title="Servidores DNSCrypt")
    dns.add(switch_row(s, "dns_cloudflare", "Cloudflare", "cloudflare / cloudflare-ipv4", save))
    dns.add(switch_row(s, "dns_quad9", "Quad9", "quad9-dnscrypt (filtro y sin filtro)", save))
    dns.add(switch_row(s, "dns_mullvad", "Mullvad", "mullvad-doh", save))
    dns.add(switch_row(s, "dns_adguard", "AdGuard", "adguard-dns-doh", save))
    dns.add(entry_row(s, "dns_server_extra", "Servidores extra (nombres DNSCrypt)", save))
    dns.add(switch_row(s, "anonymized_relays", "Retransmisores anónimos", "Oculta el servidor DNSCrypt con relays", save))
    dns.add(entry_row(s, "relay_names", "Nombres de retransmisores", save))
    dns.add(switch_row(s, "prevent_dns_leak", "Prevenir fugas DNS", "Redirige el puerto 53 al DNS cifrado", save))
    fast.add(dns)

    tor = Adw.PreferencesGroup(title="Configuración de Tor")
    tor.add(switch_row(s, "route_all_tor", "Redirigir todo el tráfico a través de Tor", "NAT transparente en modo sistema", save))
    tor.add(text_row(s, "tor_sites_unlock", "Seleccionar sitios", "Entran en el PAC (el navegador no lo usa solo; copia la URL en Inicio)", save))
    tor.add(text_row(s, "tor_sites_exclude", "Excluir páginas web", "Dominios DIRECTO en el PAC", save))
    tor.add(switch_row(s, "allow_lan", "Excluir direcciones LAN", "No envía la red local por Tor", save))
    tor.add(switch_row(s, "exclude_udp", "Excluir UDP de Tor", "Necesario para llamadas; el UDP no será anónimo", save))
    tor.add(combo_row(s, "tor_bridges_mode", "Puentes", "Snowflake si hay cliente; si no, Tor arranca sin puentes", [
        ("Sin puentes", "none"),
        ("Usar lista de puentes propia", "own"),
        ("Puentes por defecto (Snowflake)", "default"),
    ], save))
    tor.add(text_row(s, "tor_bridges", "Añadir puentes", "Una línea por puente (obfs4 / snowflake / meek_lite)", save))
    fast.add(tor)

    other = Adw.PreferencesGroup(title="Otros")
    other.add(switch_row(s, "hide_to_tray", "Minimizar a la bandeja al cerrar", "Los módulos siguen en marcha; Salir los detiene", save))
    other.add(switch_row(s, "logs_realtime", "Registros en tiempo real", "Actualiza la pestaña de registros", save))
    other.add(switch_row(s, "block_lan_free_wifi", "Bloquear LAN en WiFi desconocido", "Solo permite LAN si el SSID está en la lista de confianza", save))
    other.add(text_row(s, "trusted_wifi", "WiFi de confianza", "Un SSID por línea. En esas redes se permite LAN", save))
    other.add(switch_row(s, "firefox_pac", "Aplicar PAC a Firefox", "Escribe user.js con la URL del PAC (opt-in)", save))
    other.add(switch_row(s, "block_http", "Bloquear HTTP", "Corta el puerto 80 (tráfico sin cifrar)", save))
    other.add(combo_row(s, "theme", "Tema", "", [
        ("Noche", "night"),
        ("Día", "day"),
        ("Automático", "auto"),
    ], save))
    fast.add(other)
    pages.append(fast)

    common = Adw.PreferencesPage(title="Comunes", icon_name="applications-system-symbolic")
    root = Adw.PreferencesGroup(title="Privilegios de superusuario")
    root.add(switch_row(s, "system_mode", "Ejecutar módulos como superusuario", "tor.service + DNS global y nftables (pkexec)", save))
    common.add(root)
    proxy = Adw.PreferencesGroup(title="Proxy")
    proxy.add(switch_row(s, "use_socks5_proxy", "Usar proxy SOCKS5", "Tor / DNSCrypt / I2P salen por este proxy (VPN)", save))
    proxy.add(entry_row(s, "socks5_address", "Servidor SOCKS5 (host:puerto)", save))
    common.add(proxy)
    rest = Adw.PreferencesGroup(title="Otros")
    rest.add(switch_row(s, "kill_switch", "Interruptor general", "Kill-switch: corta tráfico fuera de Tor/DNS", save))
    rest.add(switch_row(s, "ks_allow_dhcp", "Permitir DHCP con kill-switch", "Puertos 67/68 para poder conectar WiFi nuevo", save))
    rest.add(switch_row(s, "ks_allow_ntp", "Permitir NTP con kill-switch", "UDP/123 para la hora", save))
    rest.add(switch_row(s, "ks_allow_captive", "Permitir portal cautivo", "HTTP/HTTPS a la pasarela de la red", save))
    rest.add(switch_row(s, "refresh_rules", "Refrescar reglas", "Instala un dispatcher de NetworkManager y reaplica nft/DNS al cambiar de red", save))
    common.add(rest)
    pages.append(common)

    dpage = Adw.PreferencesPage(title="DNSCrypt", icon_name="network-workgroup-symbolic")
    note = Adw.PreferencesGroup(title="¡Solo para usuarios avanzados!")
    dpage.add(note)
    glob = Adw.PreferencesGroup(title="Ajustes globales")
    glob.add(entry_row(s, "listen_port", "Puerto local", save))
    dpage.add(glob)
    req = Adw.PreferencesGroup(title="Tipos de servidor")
    req.add(switch_row(s, "dnscrypt_servers", "Servidores DNSCrypt", "Protocolo DNSCrypt", save))
    req.add(switch_row(s, "doh_servers", "Servidores DoH", "DNS sobre HTTPS", save))
    req.add(switch_row(s, "odoh_servers", "Servidores ODoH", "Oblivious DoH", save))
    req.add(switch_row(s, "ipv4_servers", "Servidores IPv4", "", save))
    req.add(switch_row(s, "ipv6_servers", "Servidores IPv6", "", save))
    dpage.add(req)
    props = Adw.PreferencesGroup(title="Propiedades exigidas")
    props.add(switch_row(s, "require_dnssec", "Exigir DNSSEC", "Solo servidores que validan DNSSEC", save))
    props.add(switch_row(s, "require_nolog", "Exigir no-log", "Solo servidores que no registran consultas", save))
    props.add(switch_row(s, "require_nofilter", "Exigir no-filtro", "Desactiva bloqueo de anuncios/adultos del servidor", save))
    dpage.add(props)
    tcp = Adw.PreferencesGroup(title="TCP")
    tcp.add(switch_row(s, "force_tcp", "Forzar TCP", "Útil si UDP está bloqueado o usas Tor", save))
    dpage.add(tcp)
    dproxy = Adw.PreferencesGroup(title="Proxy HTTP/SOCKS")
    dproxy.add(switch_row(s, "enable_dnscrypt_proxy", "Proxy saliente", "DNSCrypt sale por SOCKS (p. ej. Tor)", save))
    dproxy.add(entry_row(s, "dnscrypt_proxy_port", "Puerto proxy", save))
    dpage.add(dproxy)
    dother = Adw.PreferencesGroup(title="Otros")
    dother.add(entry_row(s, "bootstrap_resolvers", "Resolvedor de respaldo", save))
    dother.add(switch_row(s, "ignore_system_dns", "Ignorar DNS del sistema", "", save))
    dother.add(switch_row(s, "http3", "HTTP/3", "DoH sobre QUIC", save))
    dother.add(switch_row(s, "dns64", "DNS64", "Para redes solo IPv6", save))
    dother.add(entry_row(s, "dns64_prefix", "Prefijo DNS64", save))
    dpage.add(dother)
    filt = Adw.PreferencesGroup(title="Filtros")
    filt.add(switch_row(s, "block_unqualified", "Bloquear no calificados", "Evita fugas de nombres locales", save))
    filt.add(switch_row(s, "block_undelegated", "Bloquear no delegados", "", save))
    filt.add(switch_row(s, "block_ipv6", "Bloquear IPv6", "Respuestas AAAA vacías", save))
    dpage.add(filt)
    lists = Adw.PreferencesGroup(title="Listas")
    lists.add(text_row(s, "blacklist", "Lista de bloqueo", "Un dominio por línea", save))
    lists.add(text_row(s, "whitelist", "Lista de permitidos", "Un dominio por línea", save))
    lists.add(text_row(s, "ipblacklist", "Lista de bloqueo de direcciones IP", "", save))
    lists.add(text_row(s, "forwarding_rules", "Reglas de reenvío", "ejemplo: lan 192.168.1.1", save))
    lists.add(text_row(s, "cloaking_rules", "Reglas de encubrimiento", "ejemplo: ads.example.com 0.0.0.0", save))
    dpage.add(lists)
    qlog = Adw.PreferencesGroup(title="Registro de consultas")
    qlog.add(switch_row(s, "enable_query_log", "Registro de consultas", "", save))
    qlog.add(entry_row(s, "ignored_qtypes", "Tipos ignorados", save))
    qlog.add(switch_row(s, "enable_nx_log", "Registro solicitudes dudosas", "", save))
    dpage.add(qlog)
    src = Adw.PreferencesGroup(title="Fuentes")
    src.add(text_row(s, "dnscrypt_sources", "Fuentes", "URLs de public-resolvers.md", save))
    src.add(entry_row(s, "refresh_delay", "Retraso de refresco (h)", save))
    src.add(text_row(s, "dnscrypt_relays", "Retransmisores DNSCrypt", "URLs de relays.md", save))
    src.add(entry_row(s, "refresh_delay_relays", "Retraso de relays (h)", save))
    dpage.add(src)
    pages.append(dpage)

    tpage = Adw.PreferencesPage(title="Tor", icon_name="network-vpn-symbolic")
    tpage.add(Adw.PreferencesGroup(title="¡Solo para usuarios avanzados!"))
    nodes = Adw.PreferencesGroup(title="Nodos")
    nodes.add(switch_row(s, "exclude_exit_nodes", "Excluir nodos de salida", "Países/nodos que no se usarán de salida", save))
    nodes.add(entry_row(s, "exclude_exit_nodes_list", "Lista ExcludeExitNodes ({es},{us})", save))
    nodes.add(switch_row(s, "exit_nodes", "Nodos de salida", "Forzar país de salida", save))
    nodes.add(entry_row(s, "exit_nodes_list", "Lista ExitNodes", save))
    nodes.add(switch_row(s, "exclude_nodes", "Excluir nodos", "", save))
    nodes.add(entry_row(s, "exclude_nodes_list", "Lista ExcludeNodes", save))
    nodes.add(switch_row(s, "entry_nodes", "Nodos de entrada", "", save))
    nodes.add(entry_row(s, "entry_nodes_list", "Lista EntryNodes", save))
    nodes.add(switch_row(s, "strict_nodes", "Nodos estrictos", "No usar otros si fallan los elegidos", save))
    tpage.add(nodes)
    tgen = Adw.PreferencesGroup(title="Configuración general")
    tgen.add(entry_row(s, "virtual_addr_network", "Red de direcciones virtuales IPv4", save))
    tgen.add(switch_row(s, "hardware_accel", "Aceleración por hardware", "", save))
    tgen.add(switch_row(s, "avoid_disk_writes", "Evitar escrituras a disco", "", save))
    tgen.add(switch_row(s, "connection_padding", "Relleno de conexiones", "", save))
    tgen.add(switch_row(s, "reduced_connection_padding", "Relleno reducido", "", save))
    tgen.add(switch_row(s, "fascist_firewall", "Cortafuegos fascista", "Solo puertos 80/443 hacia la red Tor", save))
    tgen.add(entry_row(s, "new_circuit_period", "Periodo de circuito nuevo (s)", save))
    tgen.add(entry_row(s, "max_circuit_dirtiness", "Suciedad máxima del circuito (s)", save))
    tgen.add(entry_row(s, "dormant_client_timeout", "Tiempo inactivo (min)", save))
    tgen.add(switch_row(s, "enforce_distinct_subnets", "Forzar subredes distintas", "", save))
    tgen.add(switch_row(s, "track_host_exits", "Seguir salidas de host", "", save))
    tgen.add(switch_row(s, "client_use_ipv4", "Usar IPv4", "", save))
    tgen.add(switch_row(s, "client_use_ipv6", "Usar IPv6", "", save))
    tpage.add(tgen)
    iso = Adw.PreferencesGroup(title="Aislamiento")
    iso.add(switch_row(s, "isolate_uid", "Aislar por cliente", "IsolateClientAddr / SOCKSAuth / Protocol", save))
    iso.add(switch_row(s, "isolate_dest_address", "Aislar dirección de destino", "", save))
    iso.add(switch_row(s, "isolate_dest_port", "Aislar puerto de destino", "", save))
    tpage.add(iso)
    tprox = Adw.PreferencesGroup(title="Proxies")
    tprox.add(switch_row(s, "enable_socks_proxy", "Proxy SOCKS", "", save))
    tprox.add(entry_row(s, "socks_port", "Puerto SOCKS", save))
    tprox.add(switch_row(s, "enable_http_tunnel", "Túnel HTTP", "", save))
    tprox.add(entry_row(s, "http_tunnel_port", "Puerto túnel HTTP", save))
    tprox.add(switch_row(s, "enable_transparent_proxy", "Proxy transparente", "", save))
    tprox.add(entry_row(s, "trans_port", "Puerto TransPort", save))
    tprox.add(switch_row(s, "enable_tor_dns", "Resolver DNS", "", save))
    tprox.add(entry_row(s, "tor_dns_port", "Puerto DNS de Tor", save))
    tpage.add(tprox)
    snow = Adw.PreferencesGroup(title="Snowflake")
    snow.add(combo_row(s, "snowflake_rendezvous", "Punto de servicio de conexión", "", [
        ("AMP cache", "amp"),
        ("SQS", "sqs"),
        ("Dominio fronting", "domain"),
    ], save))
    snow.add(entry_row(s, "snowflake_stun", "Servidores STUN para Snowflake", save))
    tpage.add(snow)
    tout = Adw.PreferencesGroup(title="Proxy SOCKS de salida")
    tout.add(switch_row(s, "enable_socks_output", "Proxy SOCKS de salida", "Tor over VPN / Shadowsocks", save))
    tout.add(entry_row(s, "socks5_output", "Dirección SOCKS de salida", save))
    tpage.add(tout)
    pages.append(tpage)

    ipage = Adw.PreferencesPage(title="I2P", icon_name="network-server-symbolic")
    ipage.add(Adw.PreferencesGroup(title="¡Solo para usuarios avanzados!"))
    icom = Adw.PreferencesGroup(title="Configuración general")
    icom.add(switch_row(s, "i2p_ipv4", "IPv4", "", save))
    icom.add(switch_row(s, "i2p_ipv6", "IPv6", "", save))
    icom.add(switch_row(s, "i2p_notransit", "Sin tránsito", "No reenvía tráfico de otros", save))
    icom.add(switch_row(s, "i2p_floodfill", "Floodfill", "Más carga, mejor descubrimiento", save))
    icom.add(combo_row(s, "i2p_bandwidth", "Ancho de banda", "", [
        ("Mínimo (L)", "L"),
        ("Bajo (O)", "O"),
        ("Medio (P)", "P"),
        ("Alto (X)", "X"),
    ], save))
    icom.add(entry_row(s, "i2p_share", "Porcentaje compartido", save))
    icom.add(switch_row(s, "i2p_ssu2", "SSU2", "", save))
    icom.add(switch_row(s, "i2p_ntcp2", "NTCP2", "", save))
    ipage.add(icom)
    ihttp = Adw.PreferencesGroup(title="Proxy HTTP")
    ihttp.add(switch_row(s, "i2p_http_proxy", "Proxy HTTP", "", save))
    ihttp.add(entry_row(s, "i2p_http_port", "Puerto proxy HTTP", save))
    ihttp.add(switch_row(s, "i2p_http_outproxy", "Proxy HTTP exterior", "", save))
    ihttp.add(entry_row(s, "i2p_http_outproxy_address", "Dirección del proxy HTTP exterior", save))
    ipage.add(ihttp)
    isocks = Adw.PreferencesGroup(title="Proxy SOCKS")
    isocks.add(switch_row(s, "i2p_socks_proxy", "Proxy SOCKS", "", save))
    isocks.add(entry_row(s, "i2p_socks_port", "Puerto proxy SOCKS", save))
    isocks.add(switch_row(s, "i2p_socks_outproxy", "Proxy SOCKS exterior", "", save))
    isocks.add(entry_row(s, "i2p_socks_outproxy_address", "Dirección del proxy SOCKS exterior", save))
    isocks.add(entry_row(s, "i2p_socks_outproxy_port", "Puerto proxy SOCKS exterior", save))
    ipage.add(isocks)
    iout = Adw.PreferencesGroup(title="Proxy de salida")
    iout.add(switch_row(s, "i2p_ntcpproxy_enabled", "Usar NTCP proxy", "", save))
    iout.add(entry_row(s, "i2p_ntcpproxy", "ntcpproxy", save))
    ipage.add(iout)
    iin = Adw.PreferencesGroup(title="Conexiones entrantes")
    iin.add(switch_row(s, "i2p_incoming", "Conexiones entrantes", "", save))
    iin.add(entry_row(s, "i2p_incoming_host", "Host", save))
    iin.add(entry_row(s, "i2p_incoming_port", "Puerto", save))
    ipage.add(iin)
    isam = Adw.PreferencesGroup(title="Interfaz SAM")
    isam.add(switch_row(s, "i2p_sam", "Interfaz SAM", "", save))
    isam.add(entry_row(s, "i2p_sam_port", "Puerto de la interfaz SAM", save))
    ipage.add(isam)
    iup = Adw.PreferencesGroup(title="UPnP")
    iup.add(switch_row(s, "i2p_upnp", "UPnP", "", save))
    ipage.add(iup)
    ire = Adw.PreferencesGroup(title="Resiembra")
    ire.add(switch_row(s, "i2p_reseed_verify", "Verificar resiembra", "", save))
    ipage.add(ire)
    ilim = Adw.PreferencesGroup(title="Límites")
    ilim.add(entry_row(s, "i2p_transittunnels", "Túneles de tránsito", save))
    ilim.add(entry_row(s, "i2p_openfiles", "Archivos abiertos", save))
    ilim.add(entry_row(s, "i2p_coresize", "Tamaño de core", save))
    ipage.add(ilim)
    iab = Adw.PreferencesGroup(title="Agenda")
    iab.add(entry_row(s, "i2p_addressbook_url", "URL por defecto", save))
    iab.add(entry_row(s, "i2p_subscriptions", "Suscripciones", save))
    ipage.add(iab)
    pages.append(ipage)

    fpage = Adw.PreferencesPage(title="Cortafuegos", icon_name="security-medium-symbolic")
    fw = Adw.PreferencesGroup(title="Configuración del cortafuegos")
    fw.add(switch_row(s, "firewall", "Activar cortafuegos", "Se aplica al pulsar INICIAR (pkexec)", save))
    fw.add(switch_row(s, "allow_lan", "Permitir red local, onion e i2p", "LAN y destinos .onion/.i2p", save))
    fw.add(switch_row(s, "fw_allow_onion", "Permitir sitios onion", "", save))
    fw.add(switch_row(s, "fw_allow_i2p", "Permitir sitios i2p", "", save))
    fw.add(switch_row(s, "block_ipv6", "Bloquear IPv6", "Evita fugas por IPv6", save))
    fw.add(switch_row(s, "kill_switch", "Interruptor general", "Corta lo que no sea Tor/DNS", save))
    fw.add(switch_row(s, "block_stun", "Bloquear STUN / WebRTC", "UDP 3478 y 19302", save))
    fw.add(switch_row(s, "block_mdns", "Bloquear mDNS", "224.0.0.251:5353 (descubrimiento local)", save))
    fw.add(switch_row(s, "block_llmnr", "Bloquear LLMNR", "UDP 5355", save))
    fw.add(switch_row(s, "block_http", "Bloquear HTTP", "Rechaza TCP/80", save))
    fw.add(switch_row(s, "exclude_udp", "Excluir UDP de Tor", "UDP sale en claro salvo DNS", save))
    fpage.add(fw)
    pages.append(fpage)

    return pages
