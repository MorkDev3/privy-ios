//
//  PrivyAptosError.swift
//  PrivyAptos
//
//  Error types for Privy Aptos operations.
//

import Foundation

public enum PrivyAptosError: LocalizedError, Sendable {
    case notAuthenticated
    case walletNotFound
    case walletCreationFailed(String)
    case signingFailed(String)
    case invalidResponse(String)
    case networkError(String)
    case invalidPublicKey
    case noAccessToken

    public var errorDescription: String? {
        switch self {
        case .notAuthenticated:
            return "User is not authenticated with Privy"
        case .walletNotFound:
            return "No Aptos wallet found for this user"
        case .walletCreationFailed(let msg):
            return "Failed to create Aptos wallet: \(msg)"
        case .signingFailed(let msg):
            return "Failed to sign with Aptos wallet: \(msg)"
        case .invalidResponse(let msg):
            return "Invalid API response: \(msg)"
        case .networkError(let msg):
            return "Network error: \(msg)"
        case .invalidPublicKey:
            return "Invalid or missing public key"
        case .noAccessToken:
            return "Could not obtain access token"
        }
    }
}
