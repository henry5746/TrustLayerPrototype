//
//  main.swift
//  TrustLayerPrototype
//
//  Created by Henry Pacheco-Cruz on 3/19/26.
//

import Foundation
import AppKit
import Security

struct RuleResult {
    let flags: [String]
    var isCompliant: Bool { flags.isEmpty }
}

final class RuleEngine {
    // Rule: unsigned app -> flag
    // Rule: app running outside /Applications -> flag
    func evaluate(app: NSRunningApplication) -> RuleResult {
        var flags: [String] = []

        // Determine app bundle URL and executable URL
        let bundleURL = app.bundleURL
        let executableURL = app.executableURL

        // Rule: outside standard app locations (/Applications, /System/Applications)
        if let bundleURL {
            let path = bundleURL.path
            let allowedPrefixes = ["/Applications/", "/System/Applications/"]
            let allowedExact = ["/Applications", "/System/Applications"]
            let isInAllowedPrefix = allowedPrefixes.contains { path.hasPrefix($0) }
            let isInAllowedExact = allowedExact.contains(path)
            if !(isInAllowedPrefix || isInAllowedExact) {
                flags.append("Outside standard locations: \(path)")
            }
        } else {
            flags.append("No bundle URL (likely a helper or transient process)")
        }

        // Rule: unsigned app
        if let executableURL {
            if !isCodeSigned(at: executableURL as NSURL) {
                flags.append("Unsigned executable: \(executableURL.path)")
            }
        } else {
            flags.append("No executable URL")
        }

        return RuleResult(flags: flags)
    }

    private func isCodeSigned(at url: NSURL) -> Bool {
        var staticCode: SecStaticCode? = nil
        let status = SecStaticCodeCreateWithPath(url, SecCSFlags(), &staticCode)
        guard status == errSecSuccess, let staticCode else { return false }

        // Use default flags (0) for a basic validity check. Some constants like `.basicValidate` are not available.
        let flags: SecCSFlags = SecCSFlags(rawValue: 0)
        var errors: Unmanaged<CFError>? = nil
        let result = SecStaticCodeCheckValidityWithErrors(staticCode, flags, nil, &errors)

        if result == errSecSuccess {
            return true
        }

        // If there are errors, release them and return false. This also treats ad-hoc signatures as unsigned.
        if let cfError = errors?.takeRetainedValue() {
            _ = cfError // Could be logged in the future if needed
        }
        return false
    }
}

print("Observer: Monitoring app launches via NSWorkspace.didLaunchApplicationNotification")

// Keep a strong reference to the observer so it isn't deallocated.
final class AppLaunchObserver {
    private var token: Any?

    init(workspace: NSWorkspace = .shared) {
        token = workspace.notificationCenter.addObserver(
            forName: NSWorkspace.didLaunchApplicationNotification,
            object: nil,
            queue: .main
        ) { notification in
            // Extract the launched application info
            if let userInfo = notification.userInfo,
               let app = userInfo[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication {
                let name = app.localizedName ?? "Unknown App"
                let bundleID = app.bundleIdentifier ?? "(no bundle id)"
                let pid = app.processIdentifier
                print("Launched: \(name) | bundleID=\(bundleID) | pid=\(pid)")

                // Evaluate minimal rules
                let engine = RuleEngine()
                let result = engine.evaluate(app: app)
                if result.isCompliant {
                    print("Policy: compliant")
                } else {
                    print("Policy: flags -> \(result.flags.joined(separator: "; "))")
                }
            } else {
                print("Launched: (unknown application)")
            }
        }
    }

    deinit {
        if let token {
            NSWorkspace.shared.notificationCenter.removeObserver(token)
        }
    }
}

// Focus on one observable event first: app launch.
let observer = AppLaunchObserver()

// Run loop to keep the command-line tool alive to receive notifications.
RunLoop.main.run()

