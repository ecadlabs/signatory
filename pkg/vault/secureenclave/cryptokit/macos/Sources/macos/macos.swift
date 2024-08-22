import CryptoKit
import CryptoTokenKit
import Foundation

@available(macOS 10.15, *)
typealias PrivateKey = SecureEnclave.P256.Signing.PrivateKey
@available(macOS 10.15, *)
typealias PublicKey = P256.Signing.PublicKey
@available(macOS 10.15, *)
typealias Signature = P256.Signing.ECDSASignature

@available(macOS 10.15, *)
enum Error {
  case cryptoKit(CryptoKitError)
  case cryptoTokenKit(TKError)
}

struct ErrorType {
  static let cryptoKit = 0
  static let cryptoTokenKit = 1
}

struct CryptoKitErrorType {
  static let incorrectKeySize = 0
  static let incorrectParameterSize = 1
  static let authenticationFailure = 2
  static let underlyingCoreCryptoError = 3
  static let wrapFailure = 4
  static let unwrapFailure = 5
  static let invalidParameter = 6
}

@_cdecl("deallocate")
public func deallocate(ptr: UnsafeMutableRawPointer) {
  ptr.deallocate()
}

@available(macOS 10.15, *)
@_cdecl("isAvailable")
public func isAvailable() -> Bool {
  return SecureEnclave.isAvailable
}

@available(macOS 10.15, *)
@_cdecl("errorGetType")
public func errorGetType(ptr: UnsafeRawPointer) -> Int {
  let err = ptr.bindMemory(to: Error.self, capacity: 1).pointee
  switch err {
  case .cryptoKit(_):
    return ErrorType.cryptoKit
  case .cryptoTokenKit(_):
    return ErrorType.cryptoTokenKit
  }
}

@available(macOS 10.15, *)
@_cdecl("errorGetCryptoKit")
public func errorGetCryptoKit(ptr: UnsafeRawPointer) -> UnsafeMutableRawPointer? {
  let err = ptr.bindMemory(to: Error.self, capacity: 1).pointee
  switch err {
  case .cryptoKit(let err):
    let out = UnsafeMutablePointer<CryptoKitError>.allocate(capacity: 1)
    out.initialize(to: err)
    return UnsafeMutableRawPointer(out)
  default:
    return nil
  }
}

@available(macOS 10.15, *)
@_cdecl("errorGetCryptoTokenKit")
public func errorGetCryptoTokenKit(ptr: UnsafeRawPointer) -> UnsafeMutableRawPointer? {
  let err = ptr.bindMemory(to: Error.self, capacity: 1).pointee
  switch err {
  case .cryptoTokenKit(let err):
    let out = UnsafeMutablePointer<TKError>.allocate(capacity: 1)
    out.initialize(to: err)
    return UnsafeMutableRawPointer(out)
  default:
    return nil
  }
}

@available(macOS 10.15, *)
@_cdecl("cryptoTokenKitGetCode")
public func cryptoTokenKitGetCode(ptr: UnsafeRawPointer) -> Int {
  let err = ptr.bindMemory(to: TKError.self, capacity: 1).pointee
  return err.code.rawValue
}

@available(macOS 10.15, *)
@_cdecl("cryptoKitErrorGetType")
public func cryptoKitErrorGetType(ptr: UnsafeRawPointer) -> Int {
  let err = ptr.bindMemory(to: CryptoKitError.self, capacity: 1).pointee
  switch err {
  case .incorrectKeySize:
    return CryptoKitErrorType.incorrectKeySize
  case .incorrectParameterSize:
    return CryptoKitErrorType.incorrectParameterSize
  case .authenticationFailure:
    return CryptoKitErrorType.authenticationFailure
  case .underlyingCoreCryptoError(_):
    return CryptoKitErrorType.underlyingCoreCryptoError
  case .wrapFailure:
    return CryptoKitErrorType.wrapFailure
  case .unwrapFailure:
    return CryptoKitErrorType.unwrapFailure
  case .invalidParameter:
    return CryptoKitErrorType.invalidParameter
  default:
    return -1
  }
}

@available(macOS 10.15, *)
@_cdecl("cryptoKitErrorGetUnderlyingCoreCryptoError")
public func cryptoKitErrorGetUnderlyingCoreCryptoError(ptr: UnsafeRawPointer) -> Int {
  let err = ptr.bindMemory(to: CryptoKitError.self, capacity: 1).pointee
  switch err {
  case CryptoKitError.underlyingCoreCryptoError(let code):
    return Int(code)
  default:
    return -1
  }
}

@available(macOS 10.15, *)
@_cdecl("newPrivateKey")
public func newPrivateKey(error: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
  do {
    let key = try SecureEnclave.P256.Signing.PrivateKey()
    let out = UnsafeMutablePointer<PrivateKey>.allocate(capacity: 1)
    out.initialize(to: key)
    return UnsafeMutableRawPointer(out)
  } catch let err as CryptoKitError {
    let out = UnsafeMutablePointer<Error>.allocate(capacity: 1)
    out.initialize(to: Error.cryptoKit(err))
    error.initializeMemory(as: UnsafeMutableRawPointer.self, to: UnsafeMutableRawPointer(out))
    return nil
  } catch let err as TKError {
    let out = UnsafeMutablePointer<Error>.allocate(capacity: 1)
    out.initialize(to: Error.cryptoTokenKit(err))
    error.initializeMemory(as: UnsafeMutableRawPointer.self, to: UnsafeMutableRawPointer(out))
    return nil
  } catch {
    return nil
  }
}

@available(macOS 10.15, *)
@_cdecl("newPrivateKeyFromData")
public func newPrivateKeyFromData(
  src: UnsafeRawPointer, count: Int, error: UnsafeMutableRawPointer
)
  -> UnsafeMutableRawPointer?
{
  let data = Data(bytes: src, count: count)
  do {
    let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
    let out = UnsafeMutablePointer<PrivateKey>.allocate(capacity: 1)
    out.initialize(to: key)
    return UnsafeMutableRawPointer(out)
  } catch let err as CryptoKitError {
    let out = UnsafeMutablePointer<Error>.allocate(capacity: 1)
    out.initialize(to: Error.cryptoKit(err))
    error.initializeMemory(as: UnsafeMutableRawPointer.self, to: UnsafeMutableRawPointer(out))
    return nil
  } catch let err as TKError {
    let out = UnsafeMutablePointer<Error>.allocate(capacity: 1)
    out.initialize(to: Error.cryptoTokenKit(err))
    error.initializeMemory(as: UnsafeMutableRawPointer.self, to: UnsafeMutableRawPointer(out))
    return nil
  } catch {
    return nil
  }
}

@available(macOS 10.15, *)
@_cdecl("privateKeyGetPublicKey")
public func privateKeyGetPublicKey(from: UnsafeRawPointer) -> UnsafeMutableRawPointer {
  let out = UnsafeMutablePointer<PublicKey>.allocate(capacity: 1)
  out.initialize(to: from.bindMemory(to: PrivateKey.self, capacity: 1).pointee.publicKey)
  return UnsafeMutableRawPointer(out)
}

@available(macOS 10.15, *)
@_cdecl("privateKeyGetDataRepresentation")
public func privateKeyGetDataRepresentation(from: UnsafeRawPointer) -> UnsafeMutableRawPointer {
  let out = UnsafeMutablePointer<Data>.allocate(capacity: 1)
  out.initialize(to: from.bindMemory(to: PrivateKey.self, capacity: 1).pointee.dataRepresentation)
  return UnsafeMutableRawPointer(out)
}

@available(macOS 10.15, *)
@_cdecl("publicKeyGetX963Representation")
public func publicKeyGetX963Representation(from: UnsafeRawPointer) -> UnsafeMutableRawPointer {
  let out = UnsafeMutablePointer<Data>.allocate(capacity: 1)
  out.initialize(to: from.bindMemory(to: PublicKey.self, capacity: 1).pointee.x963Representation)  // refers to an uncompressed form with 0x04 magic byte
  return UnsafeMutableRawPointer(out)
}

@available(macOS 10.15, *)
@_cdecl("publicKeyGetRawRepresentation")
public func publicKeyGetRawRepresentation(from: UnsafeRawPointer) -> UnsafeMutableRawPointer {
  let out = UnsafeMutablePointer<Data>.allocate(capacity: 1)
  out.initialize(to: from.bindMemory(to: PublicKey.self, capacity: 1).pointee.rawRepresentation)
  return UnsafeMutableRawPointer(out)
}

@available(macOS 11.0, *)
@_cdecl("publicKeyGetDerRepresentation")
public func publicKeyGetDerRepresentation(from: UnsafeRawPointer) -> UnsafeMutableRawPointer {
  let out = UnsafeMutablePointer<Data>.allocate(capacity: 1)
  out.initialize(to: from.bindMemory(to: PublicKey.self, capacity: 1).pointee.derRepresentation)
  return UnsafeMutableRawPointer(out)
}

@available(macOS 13.0, *)
@_cdecl("publicKeyGetCompressedRepresentation")
public func publicKeyGetCompressedRepresentation(from: UnsafeRawPointer) -> UnsafeMutableRawPointer
{
  let out = UnsafeMutablePointer<Data>.allocate(capacity: 1)
  out.initialize(
    to: from.bindMemory(to: PublicKey.self, capacity: 1).pointee.compressedRepresentation)
  return UnsafeMutableRawPointer(out)
}

@_cdecl("dataGetCount")
public func dataGetCount(from: UnsafeRawPointer) -> Int {
  return from.bindMemory(to: Data.self, capacity: 1).pointee.count
}

@_cdecl("dataGetBytes")
public func dataGetBytes(from: UnsafeRawPointer, to: UnsafeMutableRawPointer) {
  let data = from.bindMemory(to: Data.self, capacity: 1).pointee
  let dest = to.bindMemory(to: UInt8.self, capacity: data.count)
  data.copyBytes(to: dest, count: data.count)
}

struct Digest256: Digest {
  let bytes: (UInt64, UInt64, UInt64, UInt64)

  static var byteCount: Int {
    return 32
  }

  init(ptr: UnsafeRawBufferPointer) {
    var bytes = (UInt64(0), UInt64(0), UInt64(0), UInt64(0))
    Swift.withUnsafeMutableBytes(of: &bytes) { target in
      target.copyMemory(from: ptr)
    }
    self.bytes = bytes
  }

  var description: String {
    return "\(Self.self): \(Array(self))"
  }

  func makeIterator() -> Array<UInt8>.Iterator {
    withUnsafeBytes { (buffPtr) in
      return Array(buffPtr).makeIterator()
    }
  }

  static func == (lhs: Self, rhs: Self) -> Bool {
    return lhs.bytes == rhs.bytes
  }

  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try Swift.withUnsafeBytes(of: bytes, body)
  }

  func hash(into hasher: inout Hasher) {
    withUnsafeBytes { (buffPtr) in
      hasher.combine(bytes: buffPtr)
    }
  }
}

@available(macOS 10.15, *)
@_cdecl("privateKeySignature")
public func privateKeySignature(
  from: UnsafeRawPointer, digest: UnsafeRawPointer, error: UnsafeMutableRawPointer
)
  -> UnsafeMutableRawPointer?
{
  let key = from.bindMemory(to: PrivateKey.self, capacity: 1).pointee
  let digestBuffer = UnsafeRawBufferPointer(start: digest, count: 32)
  let hash = Digest256(ptr: digestBuffer)
  do {
    let sig = try key.signature(for: hash)
    let out = UnsafeMutablePointer<Signature>.allocate(capacity: 1)
    out.initialize(to: sig)
    return UnsafeMutableRawPointer(out)
  } catch let err as CryptoKitError {
    let out = UnsafeMutablePointer<CryptoKitError>.allocate(capacity: 1)
    out.initialize(to: err)
    error.initializeMemory(as: UnsafeMutableRawPointer.self, to: UnsafeMutableRawPointer(out))
    return nil
  } catch {
    return nil
  }
}

@available(macOS 10.15, *)
@_cdecl("signatureGetRawRepresentation")
public func signatureGetRawRepresentation(from: UnsafeRawPointer) -> UnsafeMutableRawPointer {
  let out = UnsafeMutablePointer<Data>.allocate(capacity: 1)
  out.initialize(to: from.bindMemory(to: Signature.self, capacity: 1).pointee.rawRepresentation)  // refers to an uncompressed form with 0x04 magic byte
  return UnsafeMutableRawPointer(out)
}

@available(macOS 10.15, *)
@_cdecl("signatureGetDerRepresentation")
public func signatureGetDerRepresentation(from: UnsafeRawPointer) -> UnsafeMutableRawPointer {
  let out = UnsafeMutablePointer<Data>.allocate(capacity: 1)
  out.initialize(to: from.bindMemory(to: Signature.self, capacity: 1).pointee.derRepresentation)  // refers to an uncompressed form with 0x04 magic byte
  return UnsafeMutableRawPointer(out)
}
