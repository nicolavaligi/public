import Foundation

enum AuditError: Error {
    case invalid(String)
}

func port(_ value: Substring) throws -> UInt16 {
    guard let number = UInt16(value), number > 0 else {
        throw AuditError.invalid("Porta TCP non valida.")
    }
    return number
}

func isLoopback(_ address: String) -> Bool {
    if address == "::1" || address == "0:0:0:0:0:0:0:1" { return true }
    let octets = address.split(separator: ".", omittingEmptySubsequences: false)
    return octets.count == 4 && octets.first == "127" && octets.allSatisfy { UInt8($0) != nil }
}

func auditListeners(_ input: String, allowed: Set<UInt16>) throws -> [String] {
    var findings = Set<String>()
    for line in input.split(whereSeparator: \.isNewline) {
        guard let field = line.first, "pfn".contains(field) else {
            throw AuditError.invalid("Formato inatteso. Usa l’export lsof con -F n.")
        }
        guard field == "n" else { continue }
        let endpoint = line.dropFirst()
        guard let delimiter = endpoint.lastIndex(of: ":"), delimiter != endpoint.startIndex else {
            throw AuditError.invalid("Indirizzo TCP senza porta nell’export.")
        }
        let number = try port(endpoint[endpoint.index(after: delimiter)...])
        let address = endpoint[..<delimiter].trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if !isLoopback(address) && !allowed.contains(number) {
            findings.insert("Listener non autorizzato: \(String(reflecting: String(endpoint)))")
        }
    }
    return findings.sorted()
}

func normalizedHost(_ name: String) -> String {
    let lower = name.lowercased()
    return lower.hasSuffix(".") ? String(lower.dropLast()) : lower
}

func auditHosts(_ input: String, protected: Set<String>) throws -> [String] {
    var findings: [String] = []
    for (offset, line) in input.components(separatedBy: .newlines).enumerated() {
        let record = line.prefix(while: { $0 != "#" })
        let fields = record.split(whereSeparator: \.isWhitespace)
        guard !fields.isEmpty else { continue }
        guard fields.count >= 2 else {
            throw AuditError.invalid("Voce hosts incompleta alla riga \(offset + 1).")
        }
        for alias in Set(fields.dropFirst().map { normalizedHost(String($0)) }).intersection(protected).sorted() {
            findings.append("Override alla riga \(offset + 1): \(String(reflecting: alias)) → \(String(reflecting: String(fields[0])))")
        }
    }
    return findings
}

func main(_ arguments: [String]) throws -> Int32 {
    guard arguments.count >= 2 else {
        throw AuditError.invalid("Uso: audit_rete porte export.txt [porta ...] | audit_rete hosts file [nome ...]")
    }
    let mode = arguments[0]
    let options = arguments.dropFirst(2)
    let input = try String(contentsOfFile: arguments[1], encoding: .utf8)
        .replacingOccurrences(of: "\r\n", with: "\n")
    let findings: [String]
    switch mode {
    case "porte":
        findings = try auditListeners(input, allowed: Set(options.map { try port($0[...]) }))
    case "hosts":
        let protected = Set(options.map(normalizedHost))
        guard !protected.isEmpty,
              protected.allSatisfy({ !$0.isEmpty && !$0.contains(where: \.isWhitespace) }) else {
            throw AuditError.invalid("Indica almeno un nome protetto valido.")
        }
        findings = try auditHosts(input, protected: protected)
    default:
        throw AuditError.invalid("Modalità sconosciuta. Usa porte oppure hosts.")
    }
    for finding in findings { print(finding) }
    if findings.isEmpty { print("Nessun rilievo nei controlli eseguiti.") }
    return findings.isEmpty ? 0 : 1
}

do {
    exit(try main(Array(CommandLine.arguments.dropFirst())))
} catch AuditError.invalid(let message) {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
    exit(2)
} catch {
    FileHandle.standardError.write(Data("Impossibile leggere il file di input come testo UTF-8.\n".utf8))
    exit(2)
}
