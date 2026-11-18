// sechecks: a throwaway program for the hand checks of
// crates/p-ledge/proposals/stage2-mac.md, section 1.5.
//
// It makes P-256 keys in the Secure Enclave, keeps each as a blob in a file,
// and signs with them, so that a person can see when Touch ID is asked for.
// It is not part of pledge and nothing is built on it. Read README.md first.
//
// Every call into Apple's frameworks that the design depends on is marked
// "API:" with what it is expected to do. The file was type-checked against
// the SDK (see README.md); it was never run by its author.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

// A second build (swiftc -D OTHER) is "another program" for check 3: it has
// another name and other bytes, so another ad-hoc code signature.
#if OTHER
let programName = "sechecks-other"
#else
let programName = "sechecks"
#endif

// ---------------------------------------------------------------- helpers

func fail(_ text: String) -> Never {
    FileHandle.standardError.write(Data("\(programName): \(text)\n".utf8))
    exit(2)
}

func say(_ text: String) {
    print("\(programName): \(text)")
}

/// Everything an error can tell: the domain and code are what the key holder
/// would have to tell "declined" from "nobody answered" by.
func describe(_ error: Error) -> String {
    let ns = error as NSError
    return "error domain=\(ns.domain) code=\(ns.code) text=\(ns.localizedDescription) swift=\(String(describing: error))"
}

var keysDir = FileManager.default.currentDirectoryPath + "/sechecks-keys"

func blobPath(_ name: String) -> String {
    guard !name.isEmpty, name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }) else {
        fail("a key name is letters, digits and '-'")
    }
    return keysDir + "/" + name + ".blob"
}

func readBlob(_ name: String) -> Data {
    guard let blob = FileManager.default.contents(atPath: blobPath(name)) else {
        fail("no key file \(blobPath(name))")
    }
    return blob
}

// SSH wire format: string = 4 bytes of length, then the bytes.
func sshString(_ bytes: Data) -> Data {
    var out = Data()
    var length = UInt32(bytes.count).bigEndian
    withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
    out.append(bytes)
    return out
}

func sshString(_ text: String) -> Data { sshString(Data(text.utf8)) }

/// mpint: big-endian, no leading zeros, and one zero byte in front if the
/// top bit is set (the number is positive).
func sshMpint(_ magnitude: Data) -> Data {
    var bytes = Array(magnitude.drop(while: { $0 == 0 }))
    if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
    return sshString(Data(bytes))
}

func publicBlob(_ key: P256.Signing.PublicKey) -> Data {
    // API: x963Representation is 0x04, X (32 bytes), Y (32 bytes).
    sshString("ecdsa-sha2-nistp256") + sshString("nistp256") + sshString(key.x963Representation)
}

func signatureBlob(_ signature: P256.Signing.ECDSASignature) -> Data {
    // API: rawRepresentation is r then s, 32 bytes each.
    let raw = signature.rawRepresentation
    guard raw.count == 64 else { fail("a signature of \(raw.count) bytes, expected 64") }
    let body = sshMpint(raw.prefix(32)) + sshMpint(raw.suffix(32))
    return sshString("ecdsa-sha2-nistp256") + sshString(body)
}

// ------------------------------------------------------------------- keys

/// A fresh context for one signature. Never kept.
func context(reason: String) -> LAContext {
    let context = LAContext()
    // API: the text of the system's prompt when a key with a presence flag is
    // used with this context. Expected to appear after "<program> is trying to".
    context.localizedReason = reason
    // API: 0 is the default and means: a touch is not reused.
    context.touchIDAuthenticationAllowableReuseDuration = 0
    return context
}

func load(_ name: String, _ context: LAContext) -> SecureEnclave.P256.Signing.PrivateKey {
    do {
        // API: loads the wrapped key; expected NOT to prompt. The prompt is
        // expected at signature(for:).
        return try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: readBlob(name), authenticationContext: context)
    } catch {
        say("LOAD FAILED \(name): \(describe(error))")
        exit(1)
    }
}

/// make <name> none|biometry|biometry-set|presence unlocked|after-first-unlock
func make(_ args: [String]) {
    guard args.count == 3 else { fail("make <name> none|biometry|biometry-set|presence unlocked|after-first-unlock") }
    let (name, protection, accessible) = (args[0], args[1], args[2])
    guard SecureEnclave.isAvailable else { fail("this Mac has no Secure Enclave") }
    guard !FileManager.default.fileExists(atPath: blobPath(name)) else { fail("\(blobPath(name)) exists") }

    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    switch protection {
    case "none": break
    // API: Touch ID only; survives a change of the enrolled fingers.
    case "biometry": flags.insert(.biometryAny)
    // API: Touch ID only; the key is dead once the enrolled fingers change.
    case "biometry-set": flags.insert(.biometryCurrentSet)
    // API: Touch ID, or the account password where Touch ID is not possible.
    case "presence": flags.insert(.userPresence)
    default: fail("protection is none, biometry, biometry-set or presence")
    }
    let protectionClass: CFString
    switch accessible {
    case "unlocked": protectionClass = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    case "after-first-unlock": protectionClass = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    default: fail("accessible is unlocked or after-first-unlock")
    }

    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, protectionClass, flags, &error) else {
        fail("SecAccessControlCreateWithFlags: \(String(describing: error?.takeRetainedValue()))")
    }
    do {
        // API: makes the key in the Secure Enclave. Expected NOT to prompt,
        // also for a key with a presence flag. If it prompts, write that down.
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try FileManager.default.createDirectory(
            atPath: keysDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // API: the wrapped key. The only thing kept; expected to be all there
        // is of the key outside the Secure Enclave (no keychain item).
        guard FileManager.default.createFile(
            atPath: blobPath(name), contents: key.dataRepresentation, attributes: [.posixPermissions: 0o600])
        else { fail("could not write \(blobPath(name))") }
        say("MADE \(name) protection=\(protection) accessible=\(accessible) file=\(blobPath(name))")
        print("ecdsa-sha2-nistp256 \(publicBlob(key.publicKey).base64EncodedString()) sechecks-\(name)")
    } catch {
        say("MAKE FAILED: \(describe(error))")
        exit(1)
    }
}

/// pub <name>: the OpenSSH public key line. Expected not to prompt.
func pub(_ args: [String]) {
    guard args.count == 1 else { fail("pub <name>") }
    let key = load(args[0], context(reason: "read a public key"))
    print("ecdsa-sha2-nistp256 \(publicBlob(key.publicKey).base64EncodedString()) sechecks-\(args[0])")
}

/// One signature over `data`, timed, with the outcome printed.
@discardableResult
func signOnce(_ key: SecureEnclave.P256.Signing.PrivateKey, _ data: Data, label: String)
    -> P256.Signing.ECDSASignature?
{
    let started = Date()
    do {
        // API: hashes `data` with SHA-256 and signs. For a key with a
        // presence flag the system's prompt is expected HERE, and the call
        // returns after the touch, or throws on cancel or timeout.
        let signature = try key.signature(for: data)
        say(String(format: "SIGNED %@ after %.1f s", label, Date().timeIntervalSince(started)))
        return signature
    } catch {
        say(String(format: "NOT SIGNED %@ after %.1f s: %@", label, Date().timeIntervalSince(started), describe(error)))
        return nil
    }
}

func wait(_ seconds: Int) {
    guard seconds > 0 else { return }
    say("waiting \(seconds) s (lock the screen now, if that is the check)")
    sleep(UInt32(seconds))
}

/// sign <name> [--reason TEXT] [--delay N] [--invalidate-after N]
func sign(_ args: [String]) {
    var rest = args
    guard !rest.isEmpty else { fail("sign <name> [--reason TEXT] [--delay N] [--invalidate-after N]") }
    let name = rest.removeFirst()
    var reason = "sign 32 test bytes with the key \(name)"
    var delay = 0
    var invalidateAfter = 0
    while !rest.isEmpty {
        let option = rest.removeFirst()
        guard !rest.isEmpty else { fail("\(option) needs a value") }
        let value = rest.removeFirst()
        switch option {
        case "--reason": reason = value
        case "--delay": delay = Int(value) ?? 0
        case "--invalidate-after": invalidateAfter = Int(value) ?? 0
        default: fail("unknown option \(option)")
        }
    }
    wait(delay)
    let context = context(reason: reason)
    let key = load(name, context)
    if invalidateAfter > 0 {
        DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(invalidateAfter)) {
            say("invalidating the context now")
            // API: expected to close an open prompt and make signature(for:) throw.
            context.invalidate()
        }
    }
    let ok = signOnce(key, Data(repeating: 0x5a, count: 32), label: name) != nil
    exit(ok ? 0 : 1)
}

/// twice <name> shared|fresh: two signatures, with one context or with two.
func twice(_ args: [String]) {
    guard args.count == 2, ["shared", "fresh"].contains(args[1]) else { fail("twice <name> shared|fresh") }
    let name = args[0]
    let data = Data(repeating: 0x5a, count: 32)
    if args[1] == "shared" {
        let key = load(name, context(reason: "sign twice with ONE context, key \(name)"))
        signOnce(key, data, label: "\(name) first, shared context")
        signOnce(key, data, label: "\(name) second, shared context")
    } else {
        signOnce(load(name, context(reason: "first of two, fresh context, key \(name)")), data, label: "\(name) first")
        signOnce(load(name, context(reason: "second of two, fresh context, key \(name)")), data, label: "\(name) second")
    }
}

/// reason <name> <characters>: a prompt text of that length, like the ones
/// pledge would use, so that one can see how much of it is shown.
func reason(_ args: [String]) {
    guard args.count == 2, let length = Int(args[1]), length >= 20 else { fail("reason <name> <characters, at least 20>") }
    var text = "approve: probe on a-long-host-name.lab.example, rt procs"
    var word = 1
    while text.count < length {
        text += " word\(word)"
        word += 1
    }
    text = String(text.prefix(length - 4)) + " END"
    say("the reason is \(text.count) characters and ends in END:")
    print(text)
    signOnce(load(args[0], context(reason: text)), Data(repeating: 0x5a, count: 32), label: args[0])
}

/// sshsig <name> <namespace> <file>: writes <file>.sig, an armoured SSHSIG
/// as `ssh-keygen -Y sign` would, for `ssh-keygen -Y verify`.
func sshsig(_ args: [String]) {
    guard args.count == 3 else { fail("sshsig <name> <namespace> <file>") }
    let (name, namespace, path) = (args[0], args[1], args[2])
    guard let message = FileManager.default.contents(atPath: path) else { fail("cannot read \(path)") }
    let key = load(name, context(reason: "make an SSH signature in \(namespace)"))
    let digest = Data(SHA512.hash(data: message))
    // What the key signs (PROTOCOL.sshsig): magic, namespace, reserved, hash name, hash.
    let signed = Data("SSHSIG".utf8) + sshString(namespace) + sshString("") + sshString("sha512") + sshString(digest)
    guard let signature = signOnce(key, signed, label: name) else { exit(1) }
    var version = UInt32(1).bigEndian
    var blob = Data("SSHSIG".utf8)
    withUnsafeBytes(of: &version) { blob.append(contentsOf: $0) }
    blob += sshString(publicBlob(key.publicKey)) + sshString(namespace) + sshString("") + sshString("sha512")
        + sshString(signatureBlob(signature))
    var text = "-----BEGIN SSH SIGNATURE-----\n"
    let encoded = Array(blob.base64EncodedString())
    for start in stride(from: 0, to: encoded.count, by: 70) {
        text += String(encoded[start..<min(start + 70, encoded.count)]) + "\n"
    }
    text += "-----END SSH SIGNATURE-----\n"
    do {
        try text.write(toFile: path + ".sig", atomically: true, encoding: .utf8)
        say("WROTE \(path).sig")
    } catch {
        fail("cannot write \(path).sig: \(error)")
    }
}

// ------------------------------------------------------------------- main

var arguments = Array(CommandLine.arguments.dropFirst())
if arguments.count >= 2, arguments[0] == "--dir" {
    keysDir = arguments[1]
    arguments.removeFirst(2)
}
guard let verb = arguments.first else {
    fail("""
        usage: \(programName) [--dir DIR] <verb> ...
          make <name> none|biometry|biometry-set|presence unlocked|after-first-unlock
          pub <name>
          sign <name> [--reason TEXT] [--delay N] [--invalidate-after N]
          twice <name> shared|fresh
          reason <name> <characters>
          sshsig <name> <namespace> <file>
        keys are files <name>.blob in DIR (default ./sechecks-keys)
        """)
}
say("pid \(getpid()), keys in \(keysDir)")
let rest = Array(arguments.dropFirst())
switch verb {
case "make": make(rest)
case "pub": pub(rest)
case "sign": sign(rest)
case "twice": twice(rest)
case "reason": reason(rest)
case "sshsig": sshsig(rest)
default: fail("unknown verb \(verb)")
}
