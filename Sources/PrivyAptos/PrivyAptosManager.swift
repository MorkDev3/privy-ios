//
//  PrivyAptosManager.swift
//  PrivyAptos
//
//  Manages Aptos embedded wallet operations via Privy's API.
//  Uses the Privy SDK's auth token and authorization signatures
//  to call wallet creation and raw signing endpoints.
//

import Foundation
import PrivySDK

/// Manages Privy Aptos embedded wallet operations (create, sign, retrieve).
///
/// The Privy iOS SDK (v2.x) does not natively support Aptos wallets.
/// This module adds Aptos support by calling Privy's wallet API directly,
/// using the SDK's `getAccessToken()` and `generateAuthorizationSignature()`
/// for authentication.
public final class PrivyAptosManager: @unchecked Sendable {
    public static let shared = PrivyAptosManager()

    private let baseUrl = "https://auth.privy.io"
    private let session = URLSession.shared

    /// Privy app ID - must be set before use
    public var appId: String = ""

    private init() {}

    // MARK: - Public API

    /// Create a new Aptos embedded wallet for the authenticated user.
    /// - Parameter user: The authenticated Privy user
    /// - Returns: The created Aptos wallet
    public func createWallet(user: any PrivyUser) async throws -> PrivyAptosWallet {
        let accessToken = try await user.getAccessToken()

        let body = CreateWalletBody(chainType: "aptos")
        let bodyData = try JSONEncoder().encode(body)

        let url = "\(baseUrl)/api/v1/wallets"

        // Generate authorization signature via SDK
        let payload = WalletApiPayload(
            version: 1,
            url: url,
            method: "POST",
            headers: [:],
            body: body
        )
        let authSignature = try await user.generateAuthorizationSignature(payload: payload)

        var request = URLRequest(url: URL(string: url)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue(appId, forHTTPHeaderField: "privy-app-id")
        request.setValue(authSignature, forHTTPHeaderField: "privy-authorization-signature")
        request.httpBody = bodyData

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw PrivyAptosError.networkError("Invalid response type")
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw PrivyAptosError.walletCreationFailed("HTTP \(httpResponse.statusCode): \(body)")
        }

        let wallet = try parseWalletResponse(data: data)
        print("[PrivyAptos] Created wallet: \(wallet.address) (id: \(wallet.id))")
        return wallet
    }

    /// Get existing Aptos wallets for the authenticated user.
    /// Checks linked accounts first, then queries the wallet API.
    /// - Parameter user: The authenticated Privy user
    /// - Returns: Array of Aptos wallets
    public func getWallets(user: any PrivyUser) async throws -> [PrivyAptosWallet] {
        // First check linked accounts for Aptos wallets
        var wallets: [PrivyAptosWallet] = []
        for account in user.linkedAccounts {
            if case .externalWallet(let w) = account {
                if isValidAptosAddress(w.address) {
                    // This could be an Aptos wallet
                    wallets.append(PrivyAptosWallet(
                        id: w.address, // External wallets don't have a Privy wallet ID
                        address: w.address,
                        publicKey: nil
                    ))
                }
            }
        }

        // Also query the wallet API for embedded Aptos wallets
        do {
            let apiWallets = try await listWalletsFromAPI(user: user)
            wallets.append(contentsOf: apiWallets)
        } catch {
            print("[PrivyAptos] Warning: Failed to list wallets from API: \(error)")
        }

        return wallets
    }

    /// Get or create an Aptos wallet for the user.
    /// Returns existing wallet if found, creates new one otherwise.
    /// - Parameter user: The authenticated Privy user
    /// - Returns: The Aptos wallet
    public func getOrCreateWallet(user: any PrivyUser) async throws -> PrivyAptosWallet {
        let existing = try await getWallets(user: user)
        if let wallet = existing.first {
            print("[PrivyAptos] Found existing wallet: \(wallet.address)")
            return wallet
        }

        print("[PrivyAptos] No existing wallet found, creating new one...")
        return try await createWallet(user: user)
    }

    /// Sign a raw hash using the Aptos embedded wallet.
    /// Uses Privy's `raw_sign` endpoint which signs with Ed25519.
    /// - Parameters:
    ///   - user: The authenticated Privy user
    ///   - walletId: The Privy wallet ID
    ///   - hash: The hash to sign (0x-prefixed hex string)
    /// - Returns: The signature as a 0x-prefixed hex string
    public func signRawHash(user: any PrivyUser, walletId: String, hash: String) async throws -> String {
        let accessToken = try await user.getAccessToken()

        let body = RawSignBody(params: RawSignParams(hash: hash))
        let bodyData = try JSONEncoder().encode(body)

        let url = "\(baseUrl)/api/v1/wallets/\(walletId)/raw_sign"

        // Generate authorization signature via SDK
        let payload = WalletApiPayload(
            version: 1,
            url: url,
            method: "POST",
            headers: [:],
            body: body
        )
        let authSignature = try await user.generateAuthorizationSignature(payload: payload)

        var request = URLRequest(url: URL(string: url)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue(appId, forHTTPHeaderField: "privy-app-id")
        request.setValue(authSignature, forHTTPHeaderField: "privy-authorization-signature")
        request.httpBody = bodyData

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw PrivyAptosError.networkError("Invalid response type")
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw PrivyAptosError.signingFailed("HTTP \(httpResponse.statusCode): \(body)")
        }

        let signResponse = try JSONDecoder().decode(RawSignResponse.self, from: data)
        let signature = signResponse.data.signature

        // Ensure 0x prefix
        let result = signature.hasPrefix("0x") ? signature : "0x\(signature)"
        print("[PrivyAptos] Signed hash successfully")
        return result
    }

    /// Get the public key for a wallet.
    /// - Parameters:
    ///   - user: The authenticated Privy user
    ///   - walletId: The Privy wallet ID
    /// - Returns: The Ed25519 public key as 0x-prefixed hex
    public func getWalletPublicKey(user: any PrivyUser, walletId: String) async throws -> String {
        let accessToken = try await user.getAccessToken()

        let url = "\(baseUrl)/api/v1/wallets/\(walletId)"

        var request = URLRequest(url: URL(string: url)!)
        request.httpMethod = "GET"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue(appId, forHTTPHeaderField: "privy-app-id")

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw PrivyAptosError.invalidPublicKey
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PrivyAptosError.invalidResponse("Invalid JSON")
        }

        // Check multiple possible field names for public key
        let pubKeyFields = ["public_key", "publicKey", "ed25519_public_key", "ed25519PublicKey"]
        for field in pubKeyFields {
            if let pk = json[field] as? String, !pk.isEmpty {
                return normalizePublicKey(pk)
            }
        }

        throw PrivyAptosError.invalidPublicKey
    }

    // MARK: - Private Helpers

    private func listWalletsFromAPI(user: any PrivyUser) async throws -> [PrivyAptosWallet] {
        let accessToken = try await user.getAccessToken()

        let url = "\(baseUrl)/api/v1/wallets"

        var request = URLRequest(url: URL(string: url)!)
        request.httpMethod = "GET"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue(appId, forHTTPHeaderField: "privy-app-id")

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            return []
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let walletsArray = json["data"] as? [[String: Any]] else {
            // Try parsing as direct array
            if let walletsArray = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                return walletsArray.compactMap { parseWalletDict($0) }
                    .filter { $0.chainType == "aptos" }
            }
            return []
        }

        return walletsArray.compactMap { parseWalletDict($0) }
            .filter { $0.chainType == "aptos" }
    }

    private func parseWalletResponse(data: Data) throws -> PrivyAptosWallet {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PrivyAptosError.invalidResponse("Invalid JSON in wallet response")
        }

        guard let id = json["id"] as? String,
              let address = json["address"] as? String else {
            throw PrivyAptosError.invalidResponse("Missing id or address in wallet response")
        }

        // Extract public key from multiple possible fields
        let pubKeyFields = ["public_key", "publicKey", "ed25519_public_key", "ed25519PublicKey"]
        var publicKey: String? = nil
        for field in pubKeyFields {
            if let pk = json[field] as? String, !pk.isEmpty {
                publicKey = normalizePublicKey(pk)
                break
            }
        }

        let chainType = json["chain_type"] as? String ?? "aptos"

        return PrivyAptosWallet(
            id: id,
            address: address,
            chainType: chainType,
            publicKey: publicKey
        )
    }

    private func parseWalletDict(_ dict: [String: Any]) -> PrivyAptosWallet? {
        guard let id = dict["id"] as? String,
              let address = dict["address"] as? String else {
            return nil
        }

        let pubKeyFields = ["public_key", "publicKey", "ed25519_public_key", "ed25519PublicKey"]
        var publicKey: String? = nil
        for field in pubKeyFields {
            if let pk = dict[field] as? String, !pk.isEmpty {
                publicKey = normalizePublicKey(pk)
                break
            }
        }

        let chainType = dict["chain_type"] as? String ?? "unknown"

        return PrivyAptosWallet(
            id: id,
            address: address,
            chainType: chainType,
            publicKey: publicKey
        )
    }

    /// Normalize an Ed25519 public key to 0x-prefixed 64-char hex.
    /// Handles hex (with/without 0x), and base64 formats.
    private func normalizePublicKey(_ raw: String) -> String {
        var hex = raw

        // Strip 0x prefix for processing
        if hex.hasPrefix("0x") {
            hex = String(hex.dropFirst(2))
        }

        // If it's valid hex of the right length, return it
        if hex.count == 64, hex.allSatisfy({ $0.isHexDigit }) {
            return "0x\(hex)"
        }

        // Handle 66-char hex with leading "00" prefix
        if hex.count == 66, hex.hasPrefix("00"), hex.allSatisfy({ $0.isHexDigit }) {
            return "0x\(String(hex.dropFirst(2)))"
        }

        // Try base64 decoding
        if let data = Data(base64Encoded: raw), data.count == 32 {
            let hexStr = data.map { String(format: "%02x", $0) }.joined()
            return "0x\(hexStr)"
        }

        // Return as-is with 0x prefix
        return raw.hasPrefix("0x") ? raw : "0x\(raw)"
    }

    private func isValidAptosAddress(_ address: String) -> Bool {
        guard address.hasPrefix("0x") else { return false }
        let hex = address.dropFirst(2)
        guard hex.count >= 1 && hex.count <= 64 else { return false }
        return hex.allSatisfy { $0.isHexDigit }
    }
}

// MARK: - Request/Response Types

private struct CreateWalletBody: Encodable, Sendable {
    let chainType: String

    enum CodingKeys: String, CodingKey {
        case chainType = "chain_type"
    }
}

private struct RawSignBody: Encodable, Sendable {
    let params: RawSignParams
}

private struct RawSignParams: Encodable, Sendable {
    let hash: String
}

private struct RawSignResponse: Decodable, Sendable {
    let data: RawSignData
}

private struct RawSignData: Decodable, Sendable {
    let signature: String
    let encoding: String
}
