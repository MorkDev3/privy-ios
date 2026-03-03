//
//  PrivyAptosWallet.swift
//  PrivyAptos
//
//  Aptos embedded wallet model for Privy.
//

import Foundation

/// Represents a Privy-managed Aptos embedded wallet
public struct PrivyAptosWallet: Sendable, Codable {
    /// Privy wallet ID (used for signing requests)
    public let id: String
    /// Aptos account address (0x-prefixed hex)
    public let address: String
    /// Chain type (always "aptos")
    public let chainType: String
    /// Ed25519 public key (0x-prefixed 64-char hex), if available
    public let publicKey: String?

    public init(id: String, address: String, chainType: String = "aptos", publicKey: String? = nil) {
        self.id = id
        self.address = address
        self.chainType = chainType
        self.publicKey = publicKey
    }

    enum CodingKeys: String, CodingKey {
        case id
        case address
        case chainType = "chain_type"
        case publicKey = "public_key"
    }
}
