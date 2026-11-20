import Foundation

struct Container: Decodable {
    let name: String
    let hostConfig: HostConfig
    let mounts: [Mount]?

    enum CodingKeys: String, CodingKey {
        case name = "Name", hostConfig = "HostConfig", mounts = "Mounts"
    }
}

struct HostConfig: Decodable {
    let privileged: Bool
    let pidMode: String?
    let ipcMode: String?
    let capAdd: [String]?

    enum CodingKeys: String, CodingKey {
        case privileged = "Privileged", pidMode = "PidMode", ipcMode = "IpcMode"
        case capAdd = "CapAdd"
    }
}

struct Mount: Decodable {
    let source: String
    let destination: String

    enum CodingKeys: String, CodingKey {
        case source = "Source", destination = "Destination"
    }
}

func audit(_ container: Container) -> [String] {
    let config = container.hostConfig
    var findings: [String] = []
    if config.privileged { findings.append("modalità privilegiata") }
    if config.pidMode == "host" { findings.append("namespace PID dell’host condiviso") }
    if config.ipcMode == "host" { findings.append("namespace IPC dell’host condiviso") }
    let capabilities = Set((config.capAdd ?? []).map {
        let name = $0.uppercased()
        return name.hasPrefix("CAP_") ? String(name.dropFirst(4)) : name
    })
    for capability in capabilities.intersection(["ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE"]).sorted() {
        findings.append("capability aggiunta: \(capability)")
    }
    if (container.mounts ?? []).contains(where: {
        [$0.source, $0.destination].contains { ($0 as NSString).lastPathComponent == "docker.sock" }
    }) {
        findings.append("mount associato a docker.sock")
    }
    return findings
}

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("Uso: audit_docker inspect.json\n".utf8))
    exit(2)
}

do {
    let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
    let containers = try JSONDecoder().decode([Container].self, from: data)
    guard !containers.isEmpty else {
        FileHandle.standardError.write(Data("Nessun container nell’export.\n".utf8))
        exit(2)
    }
    var total = 0
    for container in containers {
        for finding in audit(container) {
            print("\(String(reflecting: container.name)): \(finding)")
            total += 1
        }
    }
    if total == 0 { print("Nessun rilievo nei controlli eseguiti.") }
    exit(total == 0 ? 0 : 1)
} catch {
    FileHandle.standardError.write(Data("Impossibile leggere un export docker inspect valido.\n".utf8))
    exit(2)
}
