#ifndef FLUTTER_PLUGIN_RD_ENGINE_TEXTURE_PLUGIN_H_
#define FLUTTER_PLUGIN_RD_ENGINE_TEXTURE_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <windows.h>

namespace rd_engine_texture {

struct Presentation;
struct PlatformState;
struct ModuleLease;

class RdEngineTexturePlugin final : public flutter::Plugin {
public:
  using MethodResult = flutter::MethodResult<flutter::EncodableValue>;
  using MethodResultPtr = std::shared_ptr<MethodResult>;

  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  explicit RdEngineTexturePlugin(flutter::PluginRegistrarWindows *registrar);
  ~RdEngineTexturePlugin() override;

  RdEngineTexturePlugin(const RdEngineTexturePlugin &) = delete;
  RdEngineTexturePlugin &operator=(const RdEngineTexturePlugin &) = delete;

  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

private:
  std::optional<LRESULT> OnTopLevelWindowProc(HWND hwnd, UINT message,
                                              WPARAM wparam, LPARAM lparam);

  void StartCreate(MethodResultPtr result);
  void
  ProcessPresentationMessage(const std::shared_ptr<Presentation> &presentation);
  void HandleCreateCompleted(const std::shared_ptr<Presentation> &presentation);
  void ProcessWakeReasons(const std::shared_ptr<Presentation> &presentation,
                          uint32_t reasons);
  void
  StartFlutterUnregister(const std::shared_ptr<Presentation> &presentation);
  void
  TryRegistrationRetired(const std::shared_ptr<Presentation> &presentation);
  void TryDispose(const std::shared_ptr<Presentation> &presentation);
  void CompleteDisposed(const std::shared_ptr<Presentation> &presentation);
  void FailPresentation(const std::shared_ptr<Presentation> &presentation,
                        const char *code, const char *message);
  void RequestClose(const std::shared_ptr<Presentation> &presentation);
  void RequestWindowClose();
  void MaybeContinueWindowClose();
  void RecoverDispatchFailures();
  std::shared_ptr<Presentation> FindPresentation(uint64_t token) const;
  bool GetFlutterAdapterLuid(uint32_t *low, int32_t *high);

  flutter::PluginRegistrarWindows *registrar_ = nullptr;
  flutter::TextureRegistrar *texture_registrar_ = nullptr;
  std::shared_ptr<PlatformState> platform_state_;
  std::shared_ptr<ModuleLease> module_;
  std::string module_error_;
  std::string module_error_code_ = "native_unavailable";
  std::unique_ptr<flutter::MethodChannel<flutter::EncodableValue>> channel_;
  int window_proc_delegate_id_ = 0;

  std::unordered_map<uint64_t, std::shared_ptr<Presentation>> presentations_;
  std::vector<std::shared_ptr<Presentation>> pending_;

  bool window_close_requested_ = false;
  bool allow_window_close_ = false;
  bool shutting_down_ = false;
};

} // namespace rd_engine_texture

#endif // FLUTTER_PLUGIN_RD_ENGINE_TEXTURE_PLUGIN_H_
