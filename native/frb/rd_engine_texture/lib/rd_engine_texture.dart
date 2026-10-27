import 'package:flutter/services.dart';

/// The native Flutter texture registration returned by rd-engine.
///
/// The presentation token is an opaque decimal native-owner token. The texture
/// id is only a Flutter texture registration id; neither value is a GPU handle
/// or a native pointer.
final class RdEngineTexturePresentation {
  const RdEngineTexturePresentation({
    required this.presentationToken,
    required this.textureId,
  });

  final String presentationToken;
  final int textureId;
}

/// Typed Dart boundary for the Windows rd-engine texture plugin.
///
/// This package intentionally contains no decoder, transport, pixel, or GPU
/// handle API. The native side owns the presentation lease and completes
/// [dispose] only after the Flutter registration and native owner retire.
final class RdEngineTexture {
  RdEngineTexture._();

  static const MethodChannel _channel =
      MethodChannel('rd_engine/windows_texture');

  static Future<RdEngineTexturePresentation> create() async {
    final Object? raw = await _channel.invokeMethod<Object?>('create');
    if (raw is! Map) {
      throw StateError(
          'rd_engine/windows_texture returned an invalid create result');
    }

    final Object? token = raw['presentationToken'];
    final Object? textureId = raw['textureId'];
    if (token is! String || !_isDecimalToken(token)) {
      throw StateError(
          'rd_engine/windows_texture returned an invalid presentation token');
    }
    if (textureId is! int || textureId < 0) {
      throw StateError(
          'rd_engine/windows_texture returned an invalid texture id');
    }
    return RdEngineTexturePresentation(
      presentationToken: token,
      textureId: textureId,
    );
  }

  static Future<void> dispose(String presentationToken) async {
    if (!_isDecimalToken(presentationToken)) {
      throw ArgumentError.value(
        presentationToken,
        'presentationToken',
        'must be a non-zero decimal native token',
      );
    }
    await _channel.invokeMethod<void>('dispose', <String, Object?>{
      'presentationToken': presentationToken,
    });
  }

  static bool _isDecimalToken(String value) {
    if (value.isEmpty || value == '0') {
      return false;
    }
    for (final int unit in value.codeUnits) {
      if (unit < 0x30 || unit > 0x39) {
        return false;
      }
    }
    return true;
  }
}
