import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
    exit(2)
}

let arguments = CommandLine.arguments
guard (2...3).contains(arguments.count) else {
    fail("Uso: audit_certificato certificato.pem [giorni]")
}
guard let days = Int(arguments.count == 3 ? arguments[2] : "30"),
      (0...36_500).contains(days) else {
    fail("Indica una soglia tra 0 e 36500 giorni.")
}

let process = Process()
let output = Pipe()
process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
let path = URL(fileURLWithPath: arguments[1]).standardizedFileURL.path
process.arguments = ["x509", "-in", path, "-noout", "-enddate"]
process.standardOutput = output
process.standardError = FileHandle.nullDevice

do {
    try process.run()
} catch {
    fail("Impossibile avviare /usr/bin/openssl.")
}

let data = output.fileHandleForReading.readDataToEndOfFile()
process.waitUntilExit()
guard process.terminationStatus == 0,
      let line = String(data: data, encoding: .utf8),
      line.hasPrefix("notAfter=") else {
    fail("Impossibile leggere la scadenza dal certificato PEM.")
}

let formatter = DateFormatter()
formatter.locale = Locale(identifier: "en_US_POSIX")
formatter.timeZone = TimeZone(secondsFromGMT: 0)
formatter.dateFormat = "MMM d HH:mm:ss yyyy zzz"
let dateString = line.dropFirst("notAfter=".count).split(whereSeparator: \.isWhitespace).joined(separator: " ")
guard let expiry = formatter.date(from: dateString) else {
    fail("Formato di scadenza non riconosciuto.")
}

let now = Date()
let threshold = now.addingTimeInterval(TimeInterval(days) * 86_400)
let timestamp = ISO8601DateFormatter().string(from: expiry)
if expiry <= now {
    print("Certificato scaduto. Scadenza UTC: \(timestamp)")
    exit(1)
}
if expiry <= threshold {
    print("Certificato in scadenza entro \(days) giorni. Scadenza UTC: \(timestamp)")
    exit(1)
}
print("Scadenza UTC: \(timestamp)")
