slint::include_modules!();
use chrono::Local;
use rand::Rng;
use rand::thread_rng;
use slint::{ModelRc, VecModel, Model};
use std::rc::Rc;
use sysinfo::System;
use local_ip_address::local_ip;

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

    // Initial-Logs für das Dashboard beim Start incl. Detailbeschreibungen
    let log_data = Rc::new(VecModel::<LogEntry>::from(vec![
        LogEntry {
            timestamp: "09:12:04".into(),
            actor: "PID: 1024 (systemd-journal)".into(),
            pattern: "Entropy Anomalie detected".into(),
            mitigation: "Aether Sandbox Isolation".into(),
            level: "CRITICAL".into(),
            details: "ANALYSE: Ungewöhnliche Entropie-Schwankungen im System-Journal festgestellt. Der Prozess versucht verschlüsselte Speicherbereiche außerhalb seines erlaubten Scopes zu mappen. Systemsicherheit hat den Prozess isoliert.".into(),
        },
        LogEntry {
            timestamp: "09:05:42".into(),
            actor: "IP: 127.0.0.1 (Localhost)".into(),
            pattern: "Portscan Layer-4 Audit".into(),
            mitigation: "Dynamic Tarpit Delay".into(),
            level: "WARNING".into(),
            details: "ANALYSE: Lokaler Portscan auf sensitive Control-Ports erkannt. Das Verhaltensmuster weist auf ein automatisiertes Angreifer-Fuzzing hin. Die Gegenmaßnahme verlangsamt alle Antworten künstlich um 10 Sekunden (Tarpit-Verfahren).".into(),
        },
    ]));

    ui.set_logs(ModelRc::from(log_data.clone()));

    // CALLBACK 1: Registrierung der Sofortmaßnahmen aus dem Dossier-Panel
    ui.on_execute_immediate_action(|action_type, actor| {
        println!(">>> AETHER OS INTERVENTION: [{}] befohlen gegen Wirt: {}", action_type.as_str(), actor.as_str());
    });

    // CALLBACK 2: Simulation triggern
    let ui_handle = ui.as_weak();
    ui.on_trigger_simulation(move || {
        let ui = ui_handle.unwrap();
        let mut rng = thread_rng();

        let mut sys = System::new_all();
        sys.refresh_all();

        let process_list: Vec<_> = sys.processes().values().collect();
        let actor = if !process_list.is_empty() && rng.gen_bool(0.6) {
            let proc = process_list[rng.gen_range(0..process_list.len())];
            // Korrigierter Zugriff auf den Prozessnamen ohne to_string_lossy()
            format!("PID: {} ({})", proc.pid().as_u32(), proc.name().to_string())
        } else {
            match local_ip() {
                Ok(ip) => format!("IP: {} (LAN)", ip),
                Err(_) => "IP: 192.168.178.1".to_string(),
            }
        };

        // Threat Matrix Datenpool
        let threat_matrix = vec![
            (
                "Mythos-Core Code Injection",
                "eBPF Kernel Interception Block",
                "MYTHOS_CRIT",
                "WARNUNG: Ein mutierender KI-Algorithmus versucht, bösartigen Shellcode direkt über eBPF-Filter in den laufenden Linux-Kernel einzuschleusen. Die Struktur bricht bekannte Signaturen auf. Empfohlene Maßnahme: Sofortiger Hard Kill."
            ),
            (
                "Zero-Day Kernel Exploit Bypass",
                "AETHER Anti-Entropy Shielding",
                "MYTHOS_CRIT",
                "KRITISCH: Unbekannter Exploit versucht die Adressraum-Integrität des Kernels auszuhebeln. AETHER OS hat proaktiv die ASLR-Rotation verschärft. Struktur deutet auf einen gezielten, hochkomplexen Einbruchsversuch hin."
            ),
            (
                "Automated SSH Fuzzing Cascade",
                "Immediate Tarpit Isolation",
                "CRITICAL",
                "ANALYSE: Eine kaskadierende Welle von Authentifizierungsversuchen flutet den PAM-Stack. Der Ursprung versucht Passwörter im Millisekten-Takt zu erraten. IP wurde temporär in eine unendliche Antwortschleife (Tarpit) verschoben."
            ),
            (
                "Polymorphic Memory Overwrite",
                "Proactive Micro-Sandbox Spawn",
                "CRITICAL",
                "ANALYSE: Der Prozess zeigt polymorphes Verhalten und versucht einen Stack-Buffer-Overflow im Grafik-Subsystem zu erzwingen. Die Engine hat den Prozess in eine flüchtige WebAssembly-Sandbox weggesperrt."
            ),
            (
                "High-Frequency API Flooding",
                "IP Cryptographic Deflection",
                "WARNING",
                "HINWEIS: Anomal hoher Traffic auf den Core-Endpunkten des Dashboards. Die Anfragenstruktur deutet auf ein Botnetz hin. Die Verbindung wurde auf kryptografische Rätsel umgeleitet, um die Angreifer-CPU zu überlasten."
            )
        ];

        let index = rng.gen_range(0..threat_matrix.len());
        let (pattern, mitigation, level, details) = threat_matrix[index];
        let current_time = Local::now().format("%H:%M:%S").to_string();

        let new_entry = LogEntry {
            timestamp: current_time.into(),
            actor: actor.into(),
            pattern: pattern.into(),
            mitigation: mitigation.into(),
            level: level.into(),
            details: details.into(),
        };

        log_data.insert(0, new_entry);

        // Tabellenzeilen-Limit im UI-Modell einhalten
        if log_data.row_count() > 8 {
            log_data.remove(log_data.row_count() - 1);
        }

        // UI Metriken updaten
        let current_blocks: i32 = ui.get_total_blocks().parse().unwrap_or(1412);
        ui.set_total_blocks((current_blocks + 1).to_string().into());

        if rng.gen_bool(0.4) {
            let current_tarpits: i32 = ui.get_active_tarpits().parse().unwrap_or(14);
            ui.set_active_tarpits((current_tarpits + 1).to_string().into());
        }

        let current_latency: f64 = rng.gen_range(0.05..0.15);
        ui.set_latency(format!("{:.2}ms", current_latency).into());
    });

    ui.run()
}