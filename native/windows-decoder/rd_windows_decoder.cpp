/* Windows-only hardware MF/D3D11 owner. Source-only: not compiled on the
 * development host. See the private header for SDK/link requirements.
 * SDK contracts: learn.microsoft.com/windows/win32/medfound/asynchronous-mfts,
 * supporting-direct3d-11-video-decoding-in-media-foundation,
 * /api/d3d11_3/nf-d3d11_3-id3d11fence-seteventoncompletion and
 * /api/d3d11_1/nf-d3d11_1-id3d11videoprocessorenumerator1-checkvideoprocessorformatconversion.
 * No SourceReader, software MFT, CPU decoded image, polling or timed retry.
 */
#include "rd_windows_decoder.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <d3d10_1.h>
#include <d3d11_4.h>
#include <dxgi1_2.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mftransform.h>
#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <utility>
using Microsoft::WRL::ComPtr;
namespace {
constexpr uint32_t kMaxDimension = 16384;
constexpr uint64_t kMaxImageBytes = 512ull * 1024 * 1024;
constexpr uint32_t kMaxInputBytes = 32 * 1024 * 1024;
constexpr uint32_t kMaxEvents = 64;
constexpr size_t kMaxLoans = 16;
std::atomic<uint32_t> owners{0};
std::atomic<bool> quarantine{false};
std::atomic<uint64_t> next_loan{1};
rd_wd_status result(rd_wd_error* e, rd_wd_status status = RD_WD_OK,
                    uint32_t stage = RD_WD_STAGE_NONE, HRESULT hr = S_OK) {
  if (e) *e = {sizeof(*e), stage, static_cast<int32_t>(hr), 0};
  return status;
}
bool sized(const void* p, size_t size) {
  return p && *static_cast<const uint32_t*>(p) == size;
}
bool geometry(uint32_t w, uint32_t h) {
  return w && h && w <= kMaxDimension && h <= kMaxDimension &&
         uint64_t(w) * h * 4 <= kMaxImageBytes;
}
uint64_t allocate_id(std::atomic<uint64_t>& next) {
  uint64_t n = next.load();
  while (n && n != UINT64_MAX) {
    if (next.compare_exchange_weak(n, n + 1)) return n;
  }
  return 0;
}
struct Platform {
  bool com = false, mf = false;
  HRESULT start() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr; // An STA is not the persistent decoder MTA.
    com = true;
    hr = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET);
    if (FAILED(hr)) { CoUninitialize(); com = false; return hr; }
    mf = true;
    return S_OK;
  }
  HRESULT stop() {
    if (mf) {
      HRESULT hr = MFShutdown();
      if (FAILED(hr)) return hr;
      mf = false;
    }
    if (com) { CoUninitialize(); com = false; }
    return S_OK;
  }
  // Explicit stop only: a failed shutdown retains this MTA in quarantine.
};
struct DeviceSet {
  ComPtr<ID3D11Device> device;
  ComPtr<ID3D11DeviceContext> context;
  ComPtr<ID3D11Device5> device5;
  ComPtr<ID3D11DeviceContext4> context4;
  ComPtr<ID3D11Fence> fence;
  ComPtr<ID3D11VideoDevice> video;
  ComPtr<ID3D11VideoContext> video_context;
  ComPtr<ID3D11VideoContext1> video_context1;
  HANDLE fence_event = nullptr;
  DXGI_ADAPTER_DESC1 adapter{};
  D3D_FEATURE_LEVEL level{};
  HRESULT create(uint32_t low, int32_t high) {
    ComPtr<IDXGIFactory1> factory;
    HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(factory.GetAddressOf()));
    if (FAILED(hr)) return hr;
    ComPtr<IDXGIAdapter1> selected;
    for (UINT i = 0;; ++i) {
      ComPtr<IDXGIAdapter1> candidate;
      hr = factory->EnumAdapters1(i, candidate.GetAddressOf());
      if (hr == DXGI_ERROR_NOT_FOUND) break;
      if (FAILED(hr)) return hr;
      DXGI_ADAPTER_DESC1 desc{};
      hr = candidate->GetDesc1(&desc);
      if (FAILED(hr)) return hr;
      if (desc.AdapterLuid.LowPart == low && desc.AdapterLuid.HighPart == high) {
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) return DXGI_ERROR_UNSUPPORTED;
        selected = candidate; adapter = desc; break;
      }
    }
    if (!selected) return DXGI_ERROR_NOT_FOUND;
    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
    hr = D3D11CreateDevice(selected.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
        levels, 2, D3D11_SDK_VERSION, device.GetAddressOf(), &level, context.GetAddressOf());
    if (FAILED(hr)) return hr;
    ComPtr<IDXGIDevice> dxgi;
    ComPtr<IDXGIAdapter> actual;
    DXGI_ADAPTER_DESC actual_desc{};
    if (FAILED(hr = device.As(&dxgi)) || FAILED(hr = dxgi->GetAdapter(actual.GetAddressOf())) ||
        FAILED(hr = actual->GetDesc(&actual_desc))) return hr;
    if (actual_desc.AdapterLuid.LowPart != low || actual_desc.AdapterLuid.HighPart != high)
      return DXGI_ERROR_UNSUPPORTED;
    ComPtr<ID3D10Multithread> multithread;
    if (FAILED(hr = device.As(&multithread))) return hr;
    multithread->SetMultithreadProtected(TRUE);
    if (FAILED(hr = device.As(&device5)) || FAILED(hr = context.As(&context4)) ||
        FAILED(hr = device.As(&video)) || FAILED(hr = context.As(&video_context)) ||
        FAILED(hr = context.As(&video_context1))) return hr;
    hr = device5->CreateFence(0, D3D11_FENCE_FLAG_NONE, IID_PPV_ARGS(fence.GetAddressOf()));
    if (FAILED(hr)) return hr;
    fence_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    return fence_event ? S_OK : HRESULT_FROM_WIN32(GetLastError());
  }
  HRESULT release() {
    if (fence_event) {
      if (!CloseHandle(fence_event)) return HRESULT_FROM_WIN32(GetLastError());
      fence_event = nullptr;
    }
    video_context1.Reset(); video_context.Reset(); video.Reset(); fence.Reset();
    context4.Reset(); device5.Reset(); context.Reset(); device.Reset();
    return S_OK;
  }
};
struct Contract {
  uint32_t width=0, height=0, left=0, top=0, visible_width=0, visible_height=0;
  uint32_t aperture=0, primaries=0, transfer=0, matrix=0, range=0, chroma=0;
  uint32_t interlace=0, rate_num=0, rate_den=0;
};
HRESULT contract_from(IMFMediaType* type, Contract* c) {
  *c = {};
  HRESULT hr = MFGetAttributeSize(type, MF_MT_FRAME_SIZE, &c->width, &c->height);
  if (FAILED(hr) || !geometry(c->width, c->height)) return FAILED(hr) ? hr : MF_E_INVALIDMEDIATYPE;
  c->visible_width = c->width; c->visible_height = c->height;
  type->GetUINT32(MF_MT_INTERLACE_MODE, &c->interlace);
  type->GetUINT32(MF_MT_VIDEO_PRIMARIES, &c->primaries);
  type->GetUINT32(MF_MT_TRANSFER_FUNCTION, &c->transfer);
  type->GetUINT32(MF_MT_YUV_MATRIX, &c->matrix);
  type->GetUINT32(MF_MT_VIDEO_NOMINAL_RANGE, &c->range);
  type->GetUINT32(MF_MT_VIDEO_CHROMA_SITING, &c->chroma);
  MFGetAttributeRatio(type, MF_MT_FRAME_RATE, &c->rate_num, &c->rate_den);
  // Minimum display aperture takes precedence over geometric aperture. Pan-scan
  // is not enabled. Fractional offsets cannot be represented by the VP RECT.
  MFVideoArea area{};
  UINT32 bytes=0;
  hr = type->GetBlob(MF_MT_MINIMUM_DISPLAY_APERTURE, reinterpret_cast<UINT8*>(&area), sizeof(area), &bytes);
  if (hr == MF_E_ATTRIBUTENOTFOUND)
    hr = type->GetBlob(MF_MT_GEOMETRIC_APERTURE, reinterpret_cast<UINT8*>(&area), sizeof(area), &bytes);
  if (SUCCEEDED(hr)) {
    if (bytes != sizeof(area) || area.OffsetX.fract || area.OffsetY.fract ||
        area.OffsetX.value < 0 || area.OffsetY.value < 0 || area.Area.cx <= 0 || area.Area.cy <= 0)
      return MF_E_INVALIDMEDIATYPE;
    c->aperture=1; c->left=area.OffsetX.value; c->top=area.OffsetY.value;
    c->visible_width=area.Area.cx; c->visible_height=area.Area.cy;
  } else if (hr != MF_E_ATTRIBUTENOTFOUND) return hr;
  if (uint64_t(c->left)+c->visible_width > c->width ||
      uint64_t(c->top)+c->visible_height > c->height) return MF_E_INVALIDMEDIATYPE;
  return S_OK;
}
bool color_space(const Contract& c, DXGI_COLOR_SPACE_TYPE* out) {
  // No HDR truncation, unknown-range guess, 48..208->studio approximation or
  // unknown primaries->BT709 substitution. Driver conversion support is checked.
  if (c.interlace != MFVideoInterlace_Progressive ||
      (c.transfer != MFVideoTransFunc_709 && c.transfer != MFVideoTransFunc_22) ||
      c.chroma != MFVideoChromaSubsampling_MPEG2) return false;
  bool full = c.range == MFNominalRange_0_255;
  if (!full && c.range != MFNominalRange_16_235) return false;
  if (c.primaries == MFVideoPrimaries_BT709 && c.matrix == MFVideoTransferMatrix_BT709) {
    *out = full ? DXGI_COLOR_SPACE_YCBCR_FULL_G22_LEFT_P709 : DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709;
    return true;
  }
  if ((c.primaries == MFVideoPrimaries_SMPTE170M || c.primaries == MFVideoPrimaries_BT470_2_SysBG) &&
      c.matrix == MFVideoTransferMatrix_BT601) {
    *out = full ? DXGI_COLOR_SPACE_YCBCR_FULL_G22_LEFT_P601 : DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P601;
    return true;
  }
  return false;
}
HRESULT processor(DeviceSet& d, const Contract& c,
                  ComPtr<ID3D11VideoProcessorEnumerator>* enumerator,
                  ComPtr<ID3D11VideoProcessor>* process) {
  DXGI_COLOR_SPACE_TYPE input_space;
  if (!color_space(c, &input_space)) return MF_E_INVALIDMEDIATYPE;
  D3D11_VIDEO_PROCESSOR_CONTENT_DESC desc{};
  desc.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
  // This nominal rate only selects a progressive, no-history converter, never
  // a sample duration or measured content/display rate.
  desc.InputFrameRate = {c.rate_num ? c.rate_num : 1, c.rate_den ? c.rate_den : 1};
  desc.OutputFrameRate = desc.InputFrameRate;
  desc.InputWidth=c.width; desc.InputHeight=c.height;
  desc.OutputWidth=c.visible_width; desc.OutputHeight=c.visible_height;
  desc.Usage=D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
  HRESULT hr = d.video->CreateVideoProcessorEnumerator(&desc, enumerator->ReleaseAndGetAddressOf());
  if (FAILED(hr)) return hr;
  ComPtr<ID3D11VideoProcessorEnumerator1> e1;
  if (FAILED(hr = enumerator->As(&e1))) return hr;
  BOOL supported=FALSE;
  hr = e1->CheckVideoProcessorFormatConversion(DXGI_FORMAT_NV12, input_space,
      DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709, &supported);
  if (FAILED(hr) || !supported) return FAILED(hr) ? hr : DXGI_ERROR_UNSUPPORTED;
  D3D11_VIDEO_PROCESSOR_CAPS caps{};
  if (FAILED(hr = (*enumerator)->GetVideoProcessorCaps(&caps))) return hr;
  UINT index=0;
  for (; index<caps.RateConversionCapsCount; ++index) {
    D3D11_VIDEO_PROCESSOR_RATE_CONVERSION_CAPS rate{};
    if (FAILED(hr = (*enumerator)->GetVideoProcessorRateConversionCaps(index, &rate))) return hr;
    if (rate.PastFrames == 0 && rate.FutureFrames == 0) break;
  }
  if (index == caps.RateConversionCapsCount) return DXGI_ERROR_UNSUPPORTED;
  if (FAILED(hr = d.video->CreateVideoProcessor(enumerator->Get(), index, process->ReleaseAndGetAddressOf()))) return hr;
  d.video_context->VideoProcessorSetStreamFrameFormat(process->Get(), 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
  d.video_context->VideoProcessorSetStreamAutoProcessingMode(process->Get(), 0, FALSE);
  d.video_context1->VideoProcessorSetStreamColorSpace1(process->Get(), 0, input_space);
  d.video_context1->VideoProcessorSetOutputColorSpace1(process->Get(), DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709);
  return S_OK;
}
HRESULT decoder_profiles(DeviceSet& d, uint32_t codec, uint32_t width, uint32_t height,
                         uint32_t* profiles, uint32_t* configs) {
  *profiles=0; *configs=0;
  const GUID wanted = codec == RD_WD_CODEC_H264 ? D3D11_DECODER_PROFILE_H264_VLD_NOFGT : D3D11_DECODER_PROFILE_HEVC_VLD_MAIN;
  UINT count=d.video->GetVideoDecoderProfileCount();
  for (UINT i=0; i<count; ++i) {
    GUID profile{};
    HRESULT hr=d.video->GetVideoDecoderProfile(i, &profile);
    if (FAILED(hr)) return hr;
    if (profile != wanted) continue;
    BOOL supported=FALSE;
    if (FAILED(hr=d.video->CheckVideoDecoderFormat(&profile, DXGI_FORMAT_NV12, &supported))) return hr;
    if (!supported) continue;
    ++*profiles;
    D3D11_VIDEO_DECODER_DESC desc{profile, width, height, DXGI_FORMAT_NV12};
    UINT n=0;
    if (FAILED(hr=d.video->GetVideoDecoderConfigCount(&desc, &n))) return hr;
    *configs+=n;
  }
  return *profiles && *configs ? S_OK : DXGI_ERROR_UNSUPPORTED;
}
struct Activations {
  IMFActivate** values=nullptr; UINT32 count=0;
  ~Activations() {
    if(values) for (UINT32 i=0; i<count; ++i) values[i]->Release();
    CoTaskMemFree(values);
  }
  HRESULT enumerate(uint32_t codec, UINT32 flags) {
    MFT_REGISTER_TYPE_INFO input{MFMediaType_Video, codec == RD_WD_CODEC_H264 ? MFVideoFormat_H264 : MFVideoFormat_HEVC};
    return MFTEnumEx(MFT_CATEGORY_VIDEO_DECODER, flags | MFT_ENUM_FLAG_SORTANDFILTER, &input, nullptr, &values, &count);
  }
};
HRESULT shutdown_transform(ComPtr<IMFTransform>& transform, ComPtr<IMFActivate>& activation) {
  ComPtr<IMFShutdown> shutdown;
  HRESULT hr=S_OK;
  if(transform && FAILED(hr=transform.As(&shutdown)))return hr;
  // ShutdownObject is the documented teardown for an activated object. Do not
  // invoke Shutdown twice: repeated-shutdown HRESULTs are not idempotence proof.
  if(activation) hr=activation->ShutdownObject();
  else if(shutdown) hr=shutdown->Shutdown();
  if(FAILED(hr))return hr;
  if(shutdown) {
    MFSHUTDOWN_STATUS status=MFSHUTDOWN_INITIATED;
    if(FAILED(hr=shutdown->GetShutdownStatus(&status)))return hr;
    if(status!=MFSHUTDOWN_COMPLETED)return E_PENDING;
  }
  transform.Reset();activation.Reset();return S_OK;
}
HRESULT output_type(IMFTransform* mft, DWORD stream, Contract* contract) {
  for (DWORD i=0;; ++i) {
    ComPtr<IMFMediaType> type;
    HRESULT hr=mft->GetOutputAvailableType(stream, i, type.GetAddressOf());
    if (hr == MF_E_NO_MORE_TYPES) return MF_E_INVALIDMEDIATYPE;
    if (FAILED(hr)) return hr;
    GUID subtype{};
    if (FAILED(hr=type->GetGUID(MF_MT_SUBTYPE, &subtype))) return hr;
    if (subtype != MFVideoFormat_NV12) continue;
    Contract candidate;
    if (FAILED(hr=contract_from(type.Get(), &candidate))) continue;
    if (FAILED(hr=mft->SetOutputType(stream, type.Get(), 0))) continue;
    MFT_OUTPUT_STREAM_INFO allocation{};
    if (FAILED(hr=mft->GetOutputStreamInfo(stream, &allocation))) return hr;
    // The worker can alternate input/output while preserving an undelivered
    // picture. LAZY_READ permits the MFT to discard it when input continues;
    // reject that contract on initial negotiation and every stream change.
    if (allocation.dwFlags & MFT_OUTPUT_STREAM_LAZY_READ)
      return MF_E_UNSUPPORTED_D3D_TYPE;
    if (!(allocation.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES)))
      return MF_E_UNSUPPORTED_D3D_TYPE;
    *contract=candidate;
    return S_OK;
  }
}
struct Graph {
  Platform platform;
  ComPtr<IMFActivate> activation;
  ComPtr<IMFTransform> transform;
  ComPtr<IMFDXGIDeviceManager> manager;
  ComPtr<IMFMediaEventGenerator> events;
  Contract contract;
  DWORD input=0, output=0;
  rd_wd_codec_capability identity{};
  bool uncertain=false;
  HRESULT close() {
    HRESULT hr=shutdown_transform(transform, activation);
    if (FAILED(hr)) { uncertain=true; return hr; }
    events.Reset(); manager.Reset();
    hr=platform.stop();
    if (FAILED(hr)) uncertain=true;
    return hr;
  }
  HRESULT open(DeviceSet& devices, uint32_t codec, uint32_t width, uint32_t height) {
    identity={}; identity.struct_size=sizeof(identity); identity.codec=codec;
    identity.tested_width=width; identity.tested_height=height;
    HRESULT hr=platform.start();
    if (FAILED(hr)) return hr;
    if (FAILED(hr=decoder_profiles(devices, codec, width, height, &identity.decoder_profiles, &identity.decoder_configs))) return hr;
    UINT token=0;
    if (FAILED(hr=MFCreateDXGIDeviceManager(&token, manager.GetAddressOf())) ||
        FAILED(hr=manager->ResetDevice(devices.device.Get(), token))) return hr;
    Activations list;
    if (FAILED(hr=list.enumerate(codec, MFT_ENUM_FLAG_HARDWARE))) return hr;
    if (!list.count) { identity.status=RD_WD_NO_HARDWARE_DECODER; return MF_E_TOPO_CODEC_NOT_FOUND; }
    HRESULT last=MF_E_TOPO_CODEC_NOT_FOUND;
    for (UINT32 i=0; i<list.count; ++i) {
      activation=list.values[i];
      GUID clsid{};
      activation->GetGUID(MFT_TRANSFORM_CLSID_Attribute, &clsid);
      std::memcpy(identity.clsid, &clsid, sizeof(clsid));
      wchar_t name[128]{}; UINT32 length=0;
      activation->GetString(MFT_FRIENDLY_NAME_Attribute, name, 128, &length);
      std::memcpy(identity.name, name, sizeof(name)); identity.name[127]=0;
      hr=activation->ActivateObject(IID_PPV_ARGS(transform.ReleaseAndGetAddressOf()));
      if (SUCCEEDED(hr)) hr=negotiate(codec, width, height);
      if (SUCCEEDED(hr)) {
        identity.available=1; identity.evidence=RD_WD_EVIDENCE_METADATA_SUPPORTED;
        identity.hardware_async=1; identity.d3d11_aware=1; identity.native_nv12=1;
        identity.status=RD_WD_OK; identity.hresult=S_OK;
        return S_OK;
      }
      last=hr;
      identity.hresult=hr;
      identity.status=RD_WD_UNSUPPORTED_FORMAT;
      HRESULT cleanup=shutdown_transform(transform, activation);
      if (FAILED(cleanup)) { uncertain=true; return cleanup; }
      events.Reset();
    }
    return last;
  }
  HRESULT negotiate(uint32_t codec, uint32_t width, uint32_t height) {
    ComPtr<IMFAttributes> attrs;
    HRESULT hr=transform->GetAttributes(attrs.GetAddressOf());
    if (FAILED(hr)) return hr;
    UINT32 async=0, aware=0;
    if (FAILED(hr=attrs->GetUINT32(MF_TRANSFORM_ASYNC, &async)) || !async) return FAILED(hr) ? hr : E_NOINTERFACE;
    if (FAILED(hr=attrs->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK, TRUE))) return hr;
    if (FAILED(hr=attrs->GetUINT32(MF_SA_D3D11_AWARE, &aware)) || !aware) return FAILED(hr) ? hr : E_NOINTERFACE;
    if (FAILED(hr=transform.As(&events))) return hr;
    ComPtr<IMFShutdown> shutdown;
    if (FAILED(hr=transform.As(&shutdown))) return hr;
    DWORD inputs=0, outputs=0;
    if (FAILED(hr=transform->GetStreamCount(&inputs, &outputs))) return hr;
    if (inputs != 1 || outputs != 1) return MF_E_INVALIDSTREAMNUMBER;
    hr=transform->GetStreamIDs(1, &input, 1, &output);
    if (hr == E_NOTIMPL) { input=0; output=0; }
    else if (FAILED(hr)) return hr;
    if (FAILED(hr=transform->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, reinterpret_cast<ULONG_PTR>(manager.Get())))) return hr;
    ComPtr<IMFMediaType> type;
    if (FAILED(hr=MFCreateMediaType(type.GetAddressOf())) ||
        FAILED(hr=type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video)) ||
        FAILED(hr=type->SetGUID(MF_MT_SUBTYPE, codec == RD_WD_CODEC_H264 ? MFVideoFormat_H264 : MFVideoFormat_HEVC)) ||
        FAILED(hr=MFSetAttributeSize(type.Get(), MF_MT_FRAME_SIZE, width, height)) ||
        FAILED(hr=type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive)) ||
        FAILED(hr=transform->SetInputType(input, type.Get(), 0))) return hr;
    hr=output_type(transform.Get(), output, &contract);
    if (FAILED(hr)) return hr;
    MFT_OUTPUT_STREAM_INFO info{};
    if (FAILED(hr=transform->GetOutputStreamInfo(output, &info))) return hr;
    // A hardware D3D-aware decoder must allocate its native surfaces. A caller
    // supplied system-memory sample would be a different, forbidden route.
    if (!(info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES)))
      return MF_E_UNSUPPORTED_D3D_TYPE;
    return S_OK;
  }
};
/* Streaming RBSP reader: skips emulation-prevention bytes without allocating. */
struct Bits {
  const uint8_t* p; size_t n, pos=0; unsigned zeros=0, left=0; uint8_t byte=0; bool ok=true;
  uint32_t get(unsigned bits) {
    uint32_t value=0;
    for (unsigned i=0; i<bits; ++i) {
      if (!left) {
        if (pos>=n) { ok=false; return 0; }
        byte=p[pos++];
        if (zeros>=2 && byte==3) {
          if (pos>=n || p[pos]>3) { ok=false; return 0; }
          byte=p[pos++]; zeros=0;
        }
        zeros=byte==0 ? zeros+1 : 0; left=8;
      }
      value=(value<<1)|((byte>>(--left))&1);
    }
    return value;
  }
  void skip(unsigned bits) { while (bits>32 && ok) { get(32); bits-=32; } get(bits); }
  uint32_t ue() {
    unsigned zeros_count=0;
    while (ok && get(1)==0) { if (++zeros_count>30) { ok=false; return 0; } }
    uint32_t rest=get(zeros_count);
    return ((1u<<zeros_count)-1)+rest;
  }
  int32_t se() {uint32_t code=ue();return code&1 ? int32_t((code+1)/2) : -int32_t(code/2);}
};
bool sps8(uint32_t codec, const uint8_t* p, size_t n, uint32_t* profile,
          uint32_t max_width, uint32_t max_height) {
  Bits b{p,n};
  uint64_t width=0,height=0,crop_x=0,crop_y=0;
  if (codec==RD_WD_CODEC_H264) {
    *profile=b.get(8); b.skip(16); if(b.ue()>31)return false;
    if (*profile==100) {
      if (b.ue()!=1 || b.ue()!=0 || b.ue()!=0) return false;
      b.skip(1);
      if(b.get(1)) {
        for(unsigned list=0;list<8;++list) if(b.get(1)) {
          int last=8,next=8;unsigned count=list<6?16:64;
          for(unsigned i=0;i<count;++i) {
            if(next) {int delta=b.se();if(delta < -128 || delta > 127)return false;next=(last+delta+256)%256;}
            if(next)last=next;
          }
        }
      }
    } else if (*profile!=66 && *profile!=77 && *profile!=88) return false;
    if(b.ue()>12)return false;
    uint32_t order=b.ue();
    if(order==0) {if(b.ue()>12)return false;}
    else if(order==1) {
      b.skip(1);b.se();b.se();uint32_t cycle=b.ue();if(cycle>255)return false;
      for(uint32_t i=0;i<cycle;++i)b.se();
    } else if(order!=2)return false;
    if(b.ue()>16)return false;
    b.skip(1);width=(uint64_t(b.ue())+1)*16;height=(uint64_t(b.ue())+1)*16;
    if(!b.get(1))return false; // Field/MBAFF output is not the progressive route.
    b.skip(1);
    if(b.get(1)) {
      crop_x=uint64_t(b.ue())*2;crop_x+=uint64_t(b.ue())*2;
      crop_y=uint64_t(b.ue())*2;crop_y+=uint64_t(b.ue())*2;
    }
  } else {
    b.skip(4);unsigned layers=b.get(3);b.skip(1);
    b.skip(3);*profile=b.get(5);b.skip(88);
    if(*profile!=1 || layers>6)return false;
    bool profiles[7]{},levels[7]{};
    for(unsigned i=0;i<layers;++i){profiles[i]=b.get(1)!=0;levels[i]=b.get(1)!=0;}
    if(layers)b.skip((8-layers)*2);
    for(unsigned i=0;i<layers;++i){if(profiles[i])b.skip(88);if(levels[i])b.skip(8);}
    if(b.ue()>15 || b.ue()!=1)return false;
    width=b.ue();height=b.ue();
    if(b.get(1)) {
      crop_x=uint64_t(b.ue())*2;crop_x+=uint64_t(b.ue())*2;
      crop_y=uint64_t(b.ue())*2;crop_y+=uint64_t(b.ue())*2;
    }
    if(b.ue()!=0 || b.ue()!=0)return false;
  }
  // SPS admission prevents an oversized decoded allocation before the first
  // output type. Padding is permitted; visible geometry is bounded by config.
  return b.ok && width<=kMaxDimension && height<=kMaxDimension &&
      width*height*4<=kMaxImageBytes && crop_x<width && crop_y<height &&
      width-crop_x<=max_width && height-crop_y<=max_height;
}
size_t prefix(const uint8_t* p, size_t n, size_t at) {
  if (at+3<=n && p[at]==0 && p[at+1]==0) {
    if(p[at+2]==1) return 3;
    if(at+4<=n && p[at+2]==0 && p[at+3]==1) return 4;
  }
  return 0;
}
HRESULT validate_au(uint32_t codec, const uint8_t* p, size_t n, bool previous_sps,
                    bool* saw_sps, uint32_t* profile, uint32_t max_width, uint32_t max_height) {
  if (!n || !prefix(p,n,0)) return MF_E_INVALID_STREAM_DATA;
  *saw_sps=previous_sps;
  size_t at=0;
  while(at<n) {
    size_t start=at+prefix(p,n,at), end=start;
    if(start==at || start>=n) return MF_E_INVALID_STREAM_DATA;
    while(end<n && !prefix(p,n,end)) ++end;
    if(p[start]&0x80) return MF_E_INVALID_STREAM_DATA;
    unsigned kind=codec==RD_WD_CODEC_H264 ? p[start]&31 : (p[start]>>1)&63;
    size_t header=codec==RD_WD_CODEC_H264 ? 1 : 2;
    if(end-start<header || (header==2 && !(p[start+1]&7))) return MF_E_INVALID_STREAM_DATA;
    if((header==1 && (kind==0 || kind>12)) || (header==2 && ((p[start]&1)||(p[start+1]&0xf8))))
      return MF_E_INVALIDMEDIATYPE; // No SVC/MVC/multilayer expansion.
    bool sps=codec==RD_WD_CODEC_H264 ? kind==7 : kind==33;
    bool picture=codec==RD_WD_CODEC_H264 ? kind>=1 && kind<=5 : kind<=31;
    if(sps) {
      if(!sps8(codec,p+start+header,end-start-header,profile,max_width,max_height)) return MF_E_INVALIDMEDIATYPE;
      *saw_sps=true;
    }
    if(picture && !*saw_sps) return MF_E_INVALID_STREAM_DATA;
    at=end;
  }
  return S_OK;
}
} // namespace

struct rd_wd_presenter {
  struct Image { ComPtr<ID3D11Texture2D> texture; HANDLE shared=nullptr;
    uint64_t generation=0, sequence=0; int64_t pts=0; uint32_t width=0,height=0; };
  struct Loan { uint64_t id=0; ComPtr<ID3D11Texture2D> texture; };
  DeviceSet devices;
  mutable std::mutex state;
  mutable std::atomic<bool> state_pending{false};
  enum : uint32_t { WaitClosing=1, WaitProducer=2, WaitConversion=4,
    WaitProbe=8, WaitLoans=16, WaitRegistration=32, WaitUnregister=64 };
  mutable uint32_t waiting=0;
  mutable bool terminal_notified=false;
  rd_wd_error terminal_error{sizeof(rd_wd_error),RD_WD_STAGE_CLOSE,0,0};
  std::mutex gpu;
  rd_wd_wake wake=nullptr; void* wake_context=nullptr; uint64_t token=0;
  rd_wd_progress progress=nullptr;
  std::atomic<bool> dispatch_open{false}, callback_pending{false};
  std::atomic<uint32_t> wake_in_flight{0};
  std::atomic<uint64_t> wake_started{0}, wake_finished{0};
  rd_wd_presenter_stats stats{sizeof(rd_wd_presenter_stats)};
  std::unique_ptr<Image> current, pending, uncertain_image;
  std::array<Loan,kMaxLoans> loans;
  ComPtr<ID3D11VideoProcessorEnumerator> enumerator;
  ComPtr<ID3D11VideoProcessor> video_processor;
  Contract conversion{};
  ComPtr<ID3D11VideoProcessorInputView> uncertain_input;
  ComPtr<ID3D11VideoProcessorOutputView> uncertain_output;
  uint64_t generation=0, sequence=0, fence_value=0;
  bool probing=false;
  uint32_t blocked_locked() const {
    return (!stats.closing?WaitClosing:0) | (stats.producers_live?WaitProducer:0) |
      (stats.converting?WaitConversion:0) | (probing?WaitProbe:0) |
      (stats.outstanding_loans?WaitLoans:0) | (!stats.registration_retired?WaitRegistration:0) |
      (!stats.unregister_requested?WaitUnregister:0);
  }
  struct StateGuard {
    const rd_wd_presenter* owner;
    std::unique_lock<std::mutex> lock;
    explicit StateGuard(const rd_wd_presenter* p,bool nonblocking=false):owner(p),lock(p->state,std::defer_lock) {
      if(!nonblocking) lock.lock();
      else if(!lock.try_lock()) {
        // Arm before the final recheck. If the previous holder already left,
        // this attempt takes its place instead of waiting for a lost edge.
        p->state_pending.store(true);
        lock.try_lock();
      }
    }
    ~StateGuard(){unlock();}
    bool owns_lock() const {return lock.owns_lock();}
    void unlock() {
      if(!lock.owns_lock()) return;
      uint32_t retired=owner->waiting & ~owner->blocked_locked();
      owner->waiting &= ~retired;
      bool terminal=owner->stats.unconfirmed && !owner->terminal_notified;
      if(terminal) {owner->terminal_notified=true;owner->waiting=0;}
      rd_wd_error error=owner->terminal_error;
      auto callback=owner->progress;void* context=owner->wake_context;
      lock.unlock();
      bool contended=owner->state_pending.exchange(false);
      // The source's outer Rust admission/live producer still owns context.
      // Explicit unlock ends every owner access before successful delete p;
      // the later guard destructor observes !owns_lock and touches no owner.
      if(callback && (retired || contended || terminal)) callback(context,terminal?&error:nullptr);
    }
  };
  void notify(uint32_t reasons) {
    // Every source holds outer lifetime admission or a live producer. Atomics
    // avoid reacquiring state on nonblocking import/close and callback return.
    if(!dispatch_open.load()) return;
    ++wake_in_flight;++wake_started;
    wake(wake_context,token,reasons);
    ++wake_finished;
    if(wake_in_flight.fetch_sub(1)==1 && callback_pending.exchange(false))
      progress(wake_context,nullptr);
  }
  uint32_t unregister_locked() {
    if(stats.closing && !stats.producers_live && !stats.converting && !probing && !stats.unregister_requested) {
      stats.unregister_requested=1; return RD_WD_WAKE_UNREGISTER_REQUESTED;
    }
    return 0;
  }
  void uncertain(HRESULT hr,uint32_t stage=RD_WD_STAGE_RESOURCE) {
    {
      StateGuard guard(this);
      if(!stats.unconfirmed) terminal_error={sizeof(rd_wd_error),stage,static_cast<int32_t>(hr),0};
      stats.unconfirmed=1;stats.last_hresult=hr;
      quarantine.store(true);
    }
    notify(RD_WD_WAKE_STATE_CHANGED);
  }
  rd_wd_status reserve(uint64_t wanted, rd_wd_error* e) {
    StateGuard guard(this);
    if(stats.unconfirmed) return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_RESOURCE,stats.last_hresult);
    if(stats.closing) return result(e,RD_WD_CLOSING,RD_WD_STAGE_CLOSE);
    if(!wanted || generation!=wanted) return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
    if(stats.converting || pending || probing) return result(e,RD_WD_WOULD_BLOCK,RD_WD_STAGE_RESOURCE);
    stats.converting=1; return result(e);
  }
  void finish() {
    uint32_t reason;
    { StateGuard guard(this); stats.converting=0; reason=unregister_locked(); }
    if(reason) notify(reason);
  }
  HRESULT image(uint32_t width,uint32_t height,std::unique_ptr<Image>* out) {
    if(!geometry(width,height)) return E_INVALIDARG;
    std::unique_ptr<Image> img(new(std::nothrow) Image);
    if(!img) return E_OUTOFMEMORY;
    D3D11_TEXTURE2D_DESC d{};
    d.Width=width; d.Height=height; d.MipLevels=1; d.ArraySize=1;
    d.Format=DXGI_FORMAT_B8G8R8A8_UNORM; d.SampleDesc.Count=1; d.Usage=D3D11_USAGE_DEFAULT;
    d.BindFlags=D3D11_BIND_RENDER_TARGET|D3D11_BIND_SHADER_RESOURCE; d.MiscFlags=D3D11_RESOURCE_MISC_SHARED;
    HRESULT hr=devices.device->CreateTexture2D(&d,nullptr,img->texture.GetAddressOf());
    if(FAILED(hr)) return hr;
    ComPtr<IDXGIResource> resource;
    if(FAILED(hr=img->texture.As(&resource)) || FAILED(hr=resource->GetSharedHandle(&img->shared))) return hr;
    if(!img->shared) return E_FAIL;
    img->width=width; img->height=height; *out=std::move(img); return S_OK;
  }
  HRESULT completed() {
    if(fence_value==UINT64_MAX-1) return HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
    uint64_t value=++fence_value;
    HRESULT hr=devices.context4->Signal(devices.fence.Get(),value);
    if(FAILED(hr)) return hr;
    if(FAILED(hr=devices.fence->SetEventOnCompletion(value,devices.fence_event))) return hr;
    devices.context->Flush(); // Submission, not a polling wait.
    DWORD waited=WaitForSingleObject(devices.fence_event,INFINITE);
    if(waited!=WAIT_OBJECT_0) return HRESULT_FROM_WIN32(GetLastError());
    hr=devices.device->GetDeviceRemovedReason();
    if(FAILED(hr)) return hr;
    uint64_t actual=devices.fence->GetCompletedValue();
    if(actual==UINT64_MAX || actual<value) return DXGI_ERROR_DEVICE_REMOVED;
    { StateGuard guard(this); ++stats.gpu_fence_completions; }
    return S_OK;
  }
  rd_wd_status publish_image(std::unique_ptr<Image> img,uint64_t gen,int64_t pts,rd_wd_error* e) {
    {
      StateGuard guard(this);
      if(stats.closing) return result(e,RD_WD_CLOSING,RD_WD_STAGE_CLOSE);
      if(sequence==UINT64_MAX) return result(e,RD_WD_OWNER_LIMIT,RD_WD_STAGE_RESOURCE);
      img->generation=gen; img->sequence=++sequence; img->pts=pts;
      pending=std::move(img); ++stats.published_images;
    }
    notify(RD_WD_WAKE_FRAME_AVAILABLE); return result(e);
  }
};
namespace {
struct ConversionReservation { rd_wd_presenter* p; ~ConversionReservation(){p->finish();} };
/* Exactly one submission loan. Release drops only the COM reference the loan
 * holds: it is not a consumer GPU fence and it never waits for the GPU. A
 * retained loan would block registration retirement and disposal forever, so
 * this one path waits for the bounded state mutex instead of leaking. */
struct LoanReservation {
  rd_wd_presenter* p; uint64_t id=0;
  ~LoanReservation() {
    if(!id) return;
    rd_wd_presenter::StateGuard guard(p);
    for(auto& loan:p->loans) if(loan.id==id) {
      loan.texture.Reset();loan.id=0;--p->stats.outstanding_loans;return;
    }
  }
};
rd_wd_status gpu_error(rd_wd_presenter* p, HRESULT hr, rd_wd_error* e) {
  HRESULT removed=p->devices.device->GetDeviceRemovedReason();
  return result(e,FAILED(removed)?RD_WD_DEVICE_LOST:RD_WD_NATIVE_FAILURE,
                RD_WD_STAGE_RESOURCE,FAILED(removed)?removed:hr);
}
struct Events {
  std::mutex mutex; std::condition_variable idle;
  rd_wd_decoder_wake wake=nullptr; void* context=nullptr;
  uint32_t input=0, output=0, invoking=0;
  bool sink_retired=true;
  bool stopping=false, dispatch=true;
  rd_wd_decoder_stats stats{sizeof(rd_wd_decoder_stats)};
  std::atomic<uint32_t> buffers{0};
  void signal(uint32_t kind,HRESULT hr) {
    rd_wd_decoder_wake cb; void* ctx;
    {
      std::lock_guard<std::mutex> guard(mutex);
      if(!dispatch) return;
      if(FAILED(hr)) stats.last_hresult=hr;
      cb=wake; ctx=context; ++invoking;
    }
    if(cb) cb(ctx,kind,hr);
    { std::lock_guard<std::mutex> guard(mutex); --invoking; idle.notify_all(); }
  }
  void retire() {
    std::unique_lock<std::mutex> guard(mutex);
    dispatch=false; stopping=true;
    idle.wait(guard,[this]{return invoking==0;});
    wake=nullptr; context=nullptr;
  }
};
class EventSink final : public IMFAsyncCallback {
  std::atomic<ULONG> refs{1};
  ComPtr<IMFMediaEventGenerator> generator;
  std::shared_ptr<Events> state;
 public:
  EventSink(IMFMediaEventGenerator* g,std::shared_ptr<Events> s):generator(g),state(std::move(s)) {
    std::lock_guard<std::mutex> guard(state->mutex);state->sink_retired=false;
  }
  ~EventSink() {
    generator.Reset();
    std::lock_guard<std::mutex> guard(state->mutex);
    state->sink_retired=true;state->idle.notify_all();
  }
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** out) override {
    if(!out) return E_POINTER; *out=nullptr;
    if(id==__uuidof(IUnknown)||id==__uuidof(IMFAsyncCallback)) {*out=static_cast<IMFAsyncCallback*>(this);AddRef();return S_OK;}
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() override{return ++refs;}
  ULONG STDMETHODCALLTYPE Release() override{ULONG n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE GetParameters(DWORD*,DWORD*) override{return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE Invoke(IMFAsyncResult* async) override {
    ComPtr<IMFMediaEvent> event;
    HRESULT hr=generator->EndGetEvent(async,event.GetAddressOf());
    MediaEventType type=MEUnknown;
    if(SUCCEEDED(hr)) hr=event->GetType(&type);
    HRESULT event_status=S_OK;
    if(SUCCEEDED(hr)) hr=event->GetStatus(&event_status);
    if(SUCCEEDED(hr)) hr=event_status;
    uint32_t kind=RD_WD_EVENT_OTHER;
    bool again=false;
    {
      std::lock_guard<std::mutex> guard(state->mutex);
      if(state->stopping) return S_OK;
      if(FAILED(hr)) { state->stats.last_hresult=hr; kind=RD_WD_EVENT_FAILED; }
      else if(type==METransformNeedInput) {
        ++state->stats.need_input_events; kind=RD_WD_EVENT_NEED_INPUT;
        if(state->input<kMaxEvents) ++state->input; else state->stats.event_overflow=1;
      } else if(type==METransformHaveOutput) {
        ++state->stats.have_output_events; kind=RD_WD_EVENT_HAVE_OUTPUT;
        if(state->output<kMaxEvents) ++state->output; else state->stats.event_overflow=1;
      } else if(type==METransformDrainComplete) {state->stats.drain_complete=1;kind=RD_WD_EVENT_DRAIN_COMPLETE;}
      else ++state->stats.unknown_events;
      if(state->stats.event_overflow) {hr=E_UNEXPECTED;kind=RD_WD_EVENT_FAILED;state->stats.last_hresult=hr;}
      again=SUCCEEDED(hr);
    }
    state->signal(kind,hr);
    if(again) {
      // Shutdown can race this rearm. A shutdown rejection is expected only
      // after stopping was latched; otherwise it is a real worker failure.
      hr=generator->BeginGetEvent(this,nullptr);
      if(FAILED(hr)) {
        bool stopped;
        {std::lock_guard<std::mutex> guard(state->mutex);stopped=state->stopping;}
        if(!stopped) state->signal(RD_WD_EVENT_FAILED,hr);
      }
    }
    return S_OK;
  }
};
/* The only compressed buffer. On successful ProcessInput the caller's owned
 * allocation is retained until the MFT really releases it, without copying. */
class InputBuffer final : public IMFMediaBuffer {
  std::atomic<ULONG> refs{1};
  BYTE* data; DWORD length,capacity;
  rd_wd_input_release release; void* lease;
  std::shared_ptr<Events> events;
 public:
  bool armed=false;
  InputBuffer(void* d,size_t n,rd_wd_input_release r,void* l,std::shared_ptr<Events> e)
    :data(static_cast<BYTE*>(d)),length(static_cast<DWORD>(n)),capacity(static_cast<DWORD>(n)),release(r),lease(l),events(std::move(e)){}
  ~InputBuffer() {
    if(armed) {
      release(lease);
      std::lock_guard<std::mutex> guard(events->mutex);
      --events->buffers;events->idle.notify_all();
    }
  }
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** out) override {
    if(!out)return E_POINTER;*out=nullptr;
    if(id==__uuidof(IUnknown)||id==__uuidof(IMFMediaBuffer)){*out=static_cast<IMFMediaBuffer*>(this);AddRef();return S_OK;}
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() override{return ++refs;}
  ULONG STDMETHODCALLTYPE Release() override{ULONG n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE Lock(BYTE** p,DWORD* max,DWORD* current) override {
    if(!p)return E_POINTER;*p=data;if(max)*max=capacity;if(current)*current=length;return S_OK;
  }
  HRESULT STDMETHODCALLTYPE Unlock() override{return S_OK;}
  HRESULT STDMETHODCALLTYPE GetCurrentLength(DWORD* n) override{if(!n)return E_POINTER;*n=length;return S_OK;}
  HRESULT STDMETHODCALLTYPE SetCurrentLength(DWORD n) override{if(n>capacity)return E_INVALIDARG;length=n;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetMaxLength(DWORD* n) override{if(!n)return E_POINTER;*n=capacity;return S_OK;}
};
} // namespace
struct rd_wd_decoder {
  Graph graph;
  rd_wd_presenter* presenter=nullptr;
  std::shared_ptr<Events> events;
  ComPtr<EventSink> sink;
  ComPtr<IMFSample> sample;
  ComPtr<ID3D11Texture2D> texture;
  uint32_t codec=0,max_width=0,max_height=0;
  uint64_t generation=0;
  bool have_sps=false,draining=false,flushed=false;
  HRESULT cleanup() {
    {
      std::lock_guard<std::mutex> guard(events->mutex);events->stopping=true;
    }
    events->retire();
    {
      rd_wd_presenter::StateGuard guard(presenter);
      if(presenter->stats.unconfirmed) return presenter->stats.last_hresult ? presenter->stats.last_hresult : E_FAIL;
    }
    HRESULT hr=shutdown_transform(graph.transform,graph.activation);
    if(FAILED(hr)) return hr;
    graph.events.Reset(); sink.Reset(); sample.Reset(); texture.Reset();
    // EventSink destruction proves all queued/in-flight Invoke references have
    // retired, including callbacks scheduled before IMFShutdown. The release
    // callback of every input lease also returns before MFShutdown/COM teardown.
    {
      std::unique_lock<std::mutex> guard(events->mutex);
      events->idle.wait(guard,[this]{return events->sink_retired && events->buffers.load()==0;});
      events->stats.callbacks_retired=1;
    }
    graph.manager.Reset();
    return graph.platform.stop();
  }
};
extern "C" {
rd_wd_status RD_WD_CALL rd_wd_presenter_create(const rd_wd_presenter_options* o,rd_wd_presenter** out,rd_wd_error* e) {
  result(e);
  if(!out||!sized(o,sizeof(*o))||o->reserved||!o->wake||!o->progress) return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE,E_INVALIDARG);
  *out=nullptr;
  if(quarantine.load())return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_DEVICE);
  uint32_t n=owners.load();
  do {if(n>=4)return result(e,RD_WD_OWNER_LIMIT,RD_WD_STAGE_DEVICE);} while(!owners.compare_exchange_weak(n,n+1));
  auto* p=new(std::nothrow) rd_wd_presenter;
  if(!p){--owners;return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_DEVICE,E_OUTOFMEMORY);}
  HRESULT hr=p->devices.create(o->adapter_luid_low,o->adapter_luid_high);
  if(FAILED(hr)) {
    HRESULT cleanup=p->devices.release();
    if(FAILED(cleanup)){quarantine.store(true);return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_CLOSE,cleanup);}
    delete p;--owners;
    return result(e,hr==DXGI_ERROR_UNSUPPORTED||hr==DXGI_ERROR_NOT_FOUND||hr==E_NOINTERFACE?RD_WD_UNSUPPORTED_BACKEND:RD_WD_NATIVE_FAILURE,RD_WD_STAGE_DEVICE,hr);
  }
  p->wake=o->wake;p->wake_context=o->wake_context;p->progress=o->progress;p->token=o->token;
  p->stats.dispatch_open=1;p->dispatch_open.store(true);
  *out=p;return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_begin_generation(rd_wd_presenter* p,uint64_t generation,rd_wd_error* e) {
  if(!p||!generation)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
  rd_wd_presenter::StateGuard guard(p);
  if(p->stats.unconfirmed)return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_CLOSE,p->stats.last_hresult);
  if(quarantine.load())return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_CLOSE);
  if(p->stats.closing)return result(e,RD_WD_CLOSING,RD_WD_STAGE_CLOSE);
  if(p->generation||p->probing){p->waiting|=p->blocked_locked()&(p->WaitProducer|p->WaitProbe);return result(e,RD_WD_BUSY,RD_WD_STAGE_VALIDATE);}
  p->generation=generation;p->stats.producers_live=1;++p->stats.generations_started;return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_end_generation(rd_wd_presenter* p,uint64_t generation,rd_wd_error* e) {
  if(!p)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
  uint32_t reason;
  {
    rd_wd_presenter::StateGuard guard(p);
    if(p->stats.unconfirmed)return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_CLOSE,p->stats.last_hresult);
    if(!generation||generation!=p->generation)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
    if(p->stats.converting){p->waiting|=p->WaitConversion;return result(e,RD_WD_BUSY,RD_WD_STAGE_CLOSE);}
    p->generation=0;p->stats.producers_live=0;++p->stats.generations_retired;reason=p->unregister_locked();
  }
  p->notify(reason|RD_WD_WAKE_STATE_CHANGED);return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_acquire(rd_wd_presenter* p,rd_wd_frame* f,rd_wd_error* e) {
  if(!p||!sized(f,sizeof(*f)))return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_IMPORT);
  rd_wd_presenter::StateGuard guard(p,true);
  if(!guard.owns_lock())return result(e,RD_WD_BUSY,RD_WD_STAGE_IMPORT);
  if(p->stats.unconfirmed)return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_IMPORT,p->stats.last_hresult);
  if(p->stats.closing)return result(e,RD_WD_CLOSING,RD_WD_STAGE_IMPORT);
  if(!p->current&&!p->pending)return result(e,RD_WD_WOULD_BLOCK,RD_WD_STAGE_IMPORT);
  auto it=std::find_if(p->loans.begin(),p->loans.end(),[](const rd_wd_presenter::Loan& l){return !l.id;});
  if(it==p->loans.end())return result(e,RD_WD_OWNER_LIMIT,RD_WD_STAGE_IMPORT);
  uint64_t id=allocate_id(next_loan);
  if(!id)return result(e,RD_WD_OWNER_LIMIT,RD_WD_STAGE_IMPORT);
  bool promoted=bool(p->pending);
  if(promoted){if(p->current)++p->stats.superseded_images;p->current=std::move(p->pending);++p->stats.acquired_images;}
  auto& img=*p->current;it->id=id;it->texture=img.texture;
  *f={sizeof(*f),1,img.generation,img.sequence,img.pts,img.width,img.height,img.width,img.height,img.shared,id};
  ++p->stats.outstanding_loans;
  guard.unlock();if(promoted)p->notify(RD_WD_WAKE_STATE_CHANGED);return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_release(rd_wd_presenter* p,uint64_t id,rd_wd_error* e) {
  if(!p||!id)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_IMPORT);
  // This lock covers only bounded metadata and COM reference release, not any
  // SDK submission/wait. try_lock preserves the public nonblocking contract.
  rd_wd_presenter::StateGuard guard(p,true);
  if(!guard.owns_lock())return result(e,RD_WD_BUSY,RD_WD_STAGE_IMPORT);
  for(auto& l:p->loans)if(l.id==id){l.texture.Reset();l.id=0;--p->stats.outstanding_loans;return result(e);}
  return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_IMPORT);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_publish(rd_wd_presenter* p,const rd_wd_decoded_frame* f,rd_wd_error* e) {
  if(!p||!sized(f,sizeof(*f))||!f->d3d11_texture2d||!f->d3d11_device)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
  rd_wd_status status=p->reserve(f->codec_generation,e);if(status!=RD_WD_OK)return status;
  ConversionReservation reservation{p};std::lock_guard<std::mutex> gpu(p->gpu);
  ComPtr<ID3D11Texture2D> texture(static_cast<ID3D11Texture2D*>(f->d3d11_texture2d));
  ComPtr<ID3D11Device> actual;texture->GetDevice(actual.GetAddressOf());
  if(actual.Get()!=p->devices.device.Get()||f->d3d11_device!=actual.Get())return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_IMPORT,DXGI_ERROR_UNSUPPORTED);
  D3D11_TEXTURE2D_DESC desc{};texture->GetDesc(&desc);
  if(desc.Format!=DXGI_FORMAT_NV12||desc.Usage!=D3D11_USAGE_DEFAULT||desc.CPUAccessFlags||!desc.MipLevels||
      f->subresource>=uint64_t(desc.MipLevels)*desc.ArraySize||f->subresource%desc.MipLevels!=0)
    return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,MF_E_UNSUPPORTED_D3D_TYPE);
  Contract c{};
  c.width=f->coded_width;c.height=f->coded_height;c.left=f->aperture_left;c.top=f->aperture_top;
  c.visible_width=f->visible_width;c.visible_height=f->visible_height;c.primaries=f->primaries;
  c.transfer=f->transfer;c.matrix=f->matrix;c.range=f->nominal_range;c.chroma=f->chroma_siting;
  c.interlace=MFVideoInterlace_Progressive;
  if(!geometry(c.width,c.height)||!geometry(c.visible_width,c.visible_height)||
      c.width>desc.Width||c.height>desc.Height||uint64_t(c.left)+c.visible_width>c.width||
      uint64_t(c.top)+c.visible_height>c.height)return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,MF_E_INVALIDMEDIATYPE);
  HRESULT hr=S_OK;
  if(!p->video_processor||std::memcmp(&c,&p->conversion,sizeof(c))!=0) {
    if(FAILED(hr=processor(p->devices,c,&p->enumerator,&p->video_processor)))return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,hr);
    p->conversion=c;
  }
  std::unique_ptr<rd_wd_presenter::Image> img;
  if(FAILED(hr=p->image(c.visible_width,c.visible_height,&img)))return gpu_error(p,hr,e);
  D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC input{};
  input.ViewDimension=D3D11_VPIV_DIMENSION_TEXTURE2D;input.Texture2D.ArraySlice=f->subresource/desc.MipLevels;
  ComPtr<ID3D11VideoProcessorInputView> iv;
  if(FAILED(hr=p->devices.video->CreateVideoProcessorInputView(texture.Get(),p->enumerator.Get(),&input,iv.GetAddressOf())))return gpu_error(p,hr,e);
  D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC output{};output.ViewDimension=D3D11_VPOV_DIMENSION_TEXTURE2D;
  ComPtr<ID3D11VideoProcessorOutputView> ov;
  if(FAILED(hr=p->devices.video->CreateVideoProcessorOutputView(img->texture.Get(),p->enumerator.Get(),&output,ov.GetAddressOf())))return gpu_error(p,hr,e);
  RECT source{LONG(c.left),LONG(c.top),LONG(c.left+c.visible_width),LONG(c.top+c.visible_height)};
  RECT target{0,0,LONG(c.visible_width),LONG(c.visible_height)};
  p->devices.video_context->VideoProcessorSetStreamSourceRect(p->video_processor.Get(),0,TRUE,&source);
  p->devices.video_context->VideoProcessorSetStreamDestRect(p->video_processor.Get(),0,TRUE,&target);
  p->devices.video_context->VideoProcessorSetOutputTargetRect(p->video_processor.Get(),TRUE,&target);
  D3D11_VIDEO_PROCESSOR_STREAM stream{};stream.Enable=TRUE;stream.pInputSurface=iv.Get();
  hr=p->devices.video_context->VideoProcessorBlt(p->video_processor.Get(),ov.Get(),0,1,&stream);
  // Even a failed submission can leave device work uncertain. Retain all views,
  // source sample (decoder owns it), image and context if completion is unknown.
  if(SUCCEEDED(hr))hr=p->completed();
  if(FAILED(hr)) {p->uncertain_image=std::move(img);p->uncertain_input=iv;p->uncertain_output=ov;p->uncertain(hr);return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_RESOURCE,hr);}
  return p->publish_image(std::move(img),f->codec_generation,f->pts_100ns,e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_publish_bgra(rd_wd_presenter* p,const rd_wd_bgra_raster* r,rd_wd_error* e) {
  if(!p||!sized(r,sizeof(*r))||!r->data||!geometry(r->width,r->height)||r->stride<uint64_t(r->width)*4||
      uint64_t(r->stride)*(r->height-1)+uint64_t(r->width)*4>r->data_len||r->damage_left<0||r->damage_top<0||
      r->damage_right<=r->damage_left||r->damage_bottom<=r->damage_top||uint32_t(r->damage_right)>r->width||uint32_t(r->damage_bottom)>r->height)
    return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE,E_INVALIDARG);
  rd_wd_status status=p->reserve(r->codec_generation,e);if(status!=RD_WD_OK)return status;
  ConversionReservation reservation{p};std::lock_guard<std::mutex> gpu(p->gpu);
  std::unique_ptr<rd_wd_presenter::Image> img;
  HRESULT hr=p->image(r->width,r->height,&img);
  if(FAILED(hr))return gpu_error(p,hr,e);
  // Fresh immutable image requires a full upload, even for bounded damage. The
  // GPU driver captures the borrowed source before UpdateSubresource returns.
  // There is no application staging allocation or retained CPU framebuffer.
  p->devices.context->UpdateSubresource(img->texture.Get(),0,nullptr,r->data,r->stride,0);
  hr=p->completed();
  if(FAILED(hr)){p->uncertain_image=std::move(img);p->uncertain(hr);return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_RESOURCE,hr);}
  return p->publish_image(std::move(img),r->codec_generation,r->pts_100ns,e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_publish_gpu(rd_wd_presenter* p,void* renderer_output,rd_wd_set_texture set_texture,rd_wd_error* e) {
  if(!p||!renderer_output||!set_texture)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE,E_INVALIDARG);
  ComPtr<ID3D11Texture2D> texture;
  LoanReservation loan{p};
  bool promoted=false;
  {
    // The same loan protocol as rd_wd_presenter_acquire, but with no conversion
    // reservation: this call converts nothing, allocates no image and therefore
    // takes no codec generation and blocks no producer.
    rd_wd_presenter::StateGuard guard(p,true);
    if(!guard.owns_lock())return result(e,RD_WD_BUSY,RD_WD_STAGE_IMPORT);
    if(p->stats.unconfirmed)return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_IMPORT,p->stats.last_hresult);
    if(p->stats.closing)return result(e,RD_WD_CLOSING,RD_WD_STAGE_IMPORT);
    if(!p->current&&!p->pending)return result(e,RD_WD_WOULD_BLOCK,RD_WD_STAGE_IMPORT);
    auto slot=std::find_if(p->loans.begin(),p->loans.end(),[](const rd_wd_presenter::Loan& l){return !l.id;});
    if(slot==p->loans.end())return result(e,RD_WD_OWNER_LIMIT,RD_WD_STAGE_IMPORT);
    uint64_t id=allocate_id(next_loan);
    if(!id)return result(e,RD_WD_OWNER_LIMIT,RD_WD_STAGE_IMPORT);
    promoted=bool(p->pending);
    if(promoted){if(p->current)++p->stats.superseded_images;p->current=std::move(p->pending);++p->stats.acquired_images;}
    slot->id=id;slot->texture=p->current->texture;texture=slot->texture;++p->stats.outstanding_loans;
    loan.id=id; // Armed before the guard unlocks: every later path releases it.
    guard.unlock();
  }
  // A registered loan is a real blocker for registration retirement and final
  // disposal, so neither can release the device under this submission.
  if(promoted)p->notify(RD_WD_WAKE_STATE_CHANGED);
  rd_wd_status status=RD_WD_OK;
  {
    // The client copy runs on this image's own device, whose multithread
    // protected immediate context the engine also submits to; this gate only
    // keeps the engine's own submissions from interleaving with that copy.
    std::lock_guard<std::mutex> gpu(p->gpu);
    try {set_texture(renderer_output,texture.Get());}
    catch(...) {status=RD_WD_NATIVE_FAILURE;}
  }
  // No texture pointer outlives this call and published images are immutable,
  // so a later acquire cannot observe a half-submitted frame. OK is a
  // submission verdict only: the client entry point has no error channel and
  // nothing here measures physical presentation.
  if(status!=RD_WD_OK)return result(e,status,RD_WD_STAGE_IMPORT,E_FAIL);
  return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_snapshot(const rd_wd_presenter* p,rd_wd_presenter_stats* s,rd_wd_error* e) {
  if(!p||!sized(s,sizeof(*s)))return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
  rd_wd_presenter::StateGuard guard(p,true);
  if(!guard.owns_lock())return result(e,RD_WD_BUSY,RD_WD_STAGE_VALIDATE);
  *s=p->stats;s->current_present=p->current?1:0;s->pending_present=p->pending?1:0;
  s->wake_in_flight=p->wake_in_flight.load();s->wake_started=p->wake_started.load();s->wake_finished=p->wake_finished.load();
  return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_request_close(rd_wd_presenter* p,rd_wd_error* e) {
  if(!p)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_CLOSE);
  uint32_t reason=0;
  {
    rd_wd_presenter::StateGuard guard(p,true);
    if(!guard.owns_lock())return result(e,RD_WD_BUSY,RD_WD_STAGE_CLOSE);
    if(!p->stats.closing){p->stats.closing=1;reason=RD_WD_WAKE_STATE_CHANGED;}
    reason|=p->unregister_locked();
  }
  if(reason)p->notify(reason);return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_registration_retired(rd_wd_presenter* p,rd_wd_error* e) {
  if(!p)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_CLOSE);
  rd_wd_presenter::StateGuard guard(p,true);
  if(!guard.owns_lock())return result(e,RD_WD_BUSY,RD_WD_STAGE_CLOSE);
  uint32_t blockers=p->blocked_locked()&(p->WaitUnregister|p->WaitLoans|p->WaitProducer|p->WaitConversion);
  if(blockers){p->waiting|=blockers;return result(e,RD_WD_BUSY,RD_WD_STAGE_CLOSE);}
  p->stats.registration_retired=1;return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_presenter_dispose(rd_wd_presenter* p,rd_wd_error* e) {
  if(!p)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_CLOSE);
  rd_wd_presenter::StateGuard guard(p,true);
  if(!guard.owns_lock())return result(e,RD_WD_BUSY,RD_WD_STAGE_CLOSE);
  if(p->stats.unconfirmed)return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_CLOSE,p->stats.last_hresult);
  uint32_t blockers=p->blocked_locked()&(p->WaitClosing|p->WaitRegistration|p->WaitProducer|p->WaitConversion|p->WaitProbe|p->WaitLoans);
  p->waiting|=blockers;
  bool callback_busy=p->wake_in_flight.load()!=0;
  if(callback_busy) {
    p->callback_pending.store(true);
    callback_busy=p->wake_in_flight.load()!=0;
  }
  if(blockers||callback_busy)return result(e,RD_WD_BUSY,RD_WD_STAGE_CLOSE);
  p->stats.dispatch_open=0;p->dispatch_open.store(false);
  p->current.reset();p->pending.reset();p->video_processor.Reset();p->enumerator.Reset();
  HRESULT hr=p->devices.release();
  if(FAILED(hr)){
    p->terminal_error={sizeof(rd_wd_error),RD_WD_STAGE_CLOSE,static_cast<int32_t>(hr),0};
    p->stats.unconfirmed=1;p->stats.last_hresult=hr;quarantine.store(true);
    return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_CLOSE,hr);
  }
  guard.unlock();
  p->wake=nullptr;p->progress=nullptr;p->wake_context=nullptr;
  delete p;--owners;return result(e);
}
void* RD_WD_CALL rd_wd_presenter_device(rd_wd_presenter* p){return p?p->devices.device.Get():nullptr;}
rd_wd_status RD_WD_CALL rd_wd_presenter_capabilities(rd_wd_presenter* p,rd_wd_capabilities* out,rd_wd_error* e) {
  if(!p||!sized(out,sizeof(*out)))return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_CAPABILITY);
  {
    rd_wd_presenter::StateGuard guard(p);
    if(p->stats.unconfirmed)return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_CAPABILITY,p->stats.last_hresult);
    if(p->stats.closing)return result(e,RD_WD_CLOSING,RD_WD_STAGE_CLOSE);
    if(p->probing||p->generation||p->stats.converting){p->waiting|=p->blocked_locked()&(p->WaitProbe|p->WaitProducer|p->WaitConversion);return result(e,RD_WD_BUSY,RD_WD_STAGE_CAPABILITY);}
    p->probing=true;
  }
  struct EndProbe {rd_wd_presenter* p;~EndProbe(){uint32_t reason;{rd_wd_presenter::StateGuard g(p);p->probing=false;reason=p->unregister_locked();}if(reason)p->notify(reason);}} end{p};
  std::lock_guard<std::mutex> gpu(p->gpu);
  *out={};out->struct_size=sizeof(*out);out->adapter_luid_low=p->devices.adapter.AdapterLuid.LowPart;
  out->adapter_luid_high=p->devices.adapter.AdapterLuid.HighPart;out->vendor_id=p->devices.adapter.VendorId;
  out->device_id=p->devices.adapter.DeviceId;out->feature_level=p->devices.level;out->event_completion=1;
  std::unique_ptr<rd_wd_presenter::Image> image;
  HRESULT hr=p->image(1280,720,&image);
  if(FAILED(hr))return result(e,RD_WD_UNSUPPORTED_BACKEND,RD_WD_STAGE_CAPABILITY,hr);
  out->shared_texture=1;
  Contract c{};c.width=c.visible_width=1280;c.height=c.visible_height=720;
  c.primaries=MFVideoPrimaries_BT709;c.transfer=MFVideoTransFunc_709;c.matrix=MFVideoTransferMatrix_BT709;
  c.range=MFNominalRange_16_235;c.chroma=MFVideoChromaSubsampling_MPEG2;c.interlace=MFVideoInterlace_Progressive;
  ComPtr<ID3D11VideoProcessorEnumerator> enumerator;ComPtr<ID3D11VideoProcessor> process;
  if(FAILED(hr=processor(p->devices,c,&enumerator,&process)))return result(e,RD_WD_UNSUPPORTED_BACKEND,RD_WD_STAGE_CAPABILITY,hr);
  out->video_processor=1;
  for(uint32_t codec=1;codec<=2;++codec) {
    std::unique_ptr<Graph> graph(new(std::nothrow) Graph);
    if(!graph)return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_CAPABILITY,E_OUTOFMEMORY);
    hr=graph->open(p->devices,codec,1280,720);
    auto& cap=codec==1?out->h264:out->h265;
    cap=graph->identity;
    cap.status=SUCCEEDED(hr)?RD_WD_OK:(hr==MF_E_TOPO_CODEC_NOT_FOUND?RD_WD_NO_HARDWARE_DECODER:RD_WD_UNSUPPORTED_FORMAT);
    cap.hresult=hr;
    HRESULT enumeration=S_OK;
    if(graph->platform.mf) {
      Activations sync;
      enumeration=sync.enumerate(codec,MFT_ENUM_FLAG_SYNCMFT);
      if(SUCCEEDED(enumeration)) {if(codec==1)out->sync_h264_candidates=sync.count;else out->sync_h265_candidates=sync.count;}
      // Synchronous candidates are registration diagnostics only, not activated.
    }
    HRESULT cleanup=graph->uncertain?hr:graph->close();
    if(FAILED(cleanup)) {
      graph.release();p->uncertain(cleanup,RD_WD_STAGE_CLOSE);
      // The creating MTA must stay alive; Rust detects UNCONFIRMED and parks
      // the dedicated capability thread. The graph is bounded by this owner.
      return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_CLOSE,cleanup);
    }
    if(FAILED(enumeration))return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_CAPABILITY,enumeration);
  }
  return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_decoder_open(const rd_wd_decoder_options* o,rd_wd_decoder** out,rd_wd_open_report* report,rd_wd_error* e) {
  if(!out||!sized(o,sizeof(*o))||!sized(report,sizeof(*report))||!o->presenter||!o->wake||
      !geometry(o->max_width,o->max_height)||(o->codec!=1&&o->codec!=2))return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
  *out=nullptr;*report={};report->struct_size=sizeof(*report);report->cleanup=RD_WD_CLEANUP_CONFIRMED;
  auto* d=new(std::nothrow) rd_wd_decoder;
  if(!d)return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_DEVICE,E_OUTOFMEMORY);
  d->presenter=o->presenter;d->codec=o->codec;d->max_width=o->max_width;d->max_height=o->max_height;d->generation=o->generation;
  try {d->events=std::make_shared<Events>();}catch(const std::bad_alloc&){delete d;return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_DEVICE,E_OUTOFMEMORY);}
  d->events->wake=o->wake;d->events->context=o->wake_context;
  HRESULT hr=d->graph.open(o->presenter->devices,o->codec,o->max_width,o->max_height);
  if(SUCCEEDED(hr)) {
    d->sink.Attach(new(std::nothrow) EventSink(d->graph.events.Get(),d->events));
    if(!d->sink)hr=E_OUTOFMEMORY;
  }
  if(SUCCEEDED(hr))hr=d->graph.events->BeginGetEvent(d->sink.Get(),nullptr);
  if(SUCCEEDED(hr))hr=d->graph.transform->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,0);
  if(SUCCEEDED(hr))hr=d->graph.transform->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM,0);
  report->identity=d->graph.identity;
  if(FAILED(hr)) {
    HRESULT cleanup=d->graph.uncertain?hr:d->cleanup();
    if(FAILED(cleanup)){report->cleanup=RD_WD_CLEANUP_UNCONFIRMED;d->events->retire();d->presenter->uncertain(cleanup,RD_WD_STAGE_CLOSE);*out=d;}
    else delete d;
    return result(e,FAILED(cleanup)?RD_WD_RECLAMATION_UNCONFIRMED:(hr==MF_E_TOPO_CODEC_NOT_FOUND?RD_WD_NO_HARDWARE_DECODER:RD_WD_NATIVE_FAILURE),RD_WD_STAGE_DEVICE,hr);
  }
  report->cleanup=RD_WD_CLEANUP_UNKNOWN;report->identity.evidence=RD_WD_EVIDENCE_OPENED;
  {std::lock_guard<std::mutex> guard(d->events->mutex);d->events->stats.opened=1;}
  *out=d;return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_decoder_input(rd_wd_decoder* d,void* bytes,size_t size,int64_t pts,uint32_t flags,rd_wd_input_release release,void* lease,rd_wd_error* e) {
  if(!d||!bytes||!size||size>kMaxInputBytes||!release||!lease||(flags&~(RD_WD_AU_CLEAN_POINT|RD_WD_AU_CODEC_CONFIG)))
    return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
  if(d->draining||d->flushed)return result(e,RD_WD_CLOSING,RD_WD_STAGE_CLOSE);
  {
    std::lock_guard<std::mutex> guard(d->events->mutex);
    if(!d->events->input)return result(e,RD_WD_WOULD_BLOCK,RD_WD_STAGE_RESOURCE);
    --d->events->input;
  }
  bool saw_sps=false;uint32_t profile=d->graph.identity.tested_profile;
  HRESULT hr=validate_au(d->codec,static_cast<const uint8_t*>(bytes),size,d->have_sps,&saw_sps,&profile,d->max_width,d->max_height);
  if(FAILED(hr))return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_VALIDATE,hr);
  MFT_INPUT_STREAM_INFO input_info{};
  if(FAILED(hr=d->graph.transform->GetInputStreamInfo(d->graph.input,&input_info)))
    return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_RESOURCE,hr);
  if(size<input_info.cbSize || (input_info.cbAlignment && reinterpret_cast<uintptr_t>(bytes)%input_info.cbAlignment))
    return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,MF_E_BUFFERTOOSMALL);
  ComPtr<IMFSample> sample;
  if(FAILED(hr=MFCreateSample(sample.GetAddressOf())))return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_RESOURCE,hr);
  ComPtr<InputBuffer> buffer;buffer.Attach(new(std::nothrow) InputBuffer(bytes,size,release,lease,d->events));
  if(!buffer)return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_RESOURCE,E_OUTOFMEMORY);
  if(FAILED(hr=sample->AddBuffer(buffer.Get()))||FAILED(hr=sample->SetSampleTime(pts))||
      FAILED(hr=sample->SetUINT32(MFSampleExtension_CleanPoint,(flags&RD_WD_AU_CLEAN_POINT)?TRUE:FALSE)))
    return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_RESOURCE,hr);
  hr=d->graph.transform->ProcessInput(d->graph.input,sample.Get(),0);
  if(hr==MF_E_NOTACCEPTING)return result(e,RD_WD_WOULD_BLOCK,RD_WD_STAGE_RESOURCE,hr);
  if(FAILED(hr))return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_RESOURCE,hr);
  ++d->events->buffers;buffer->armed=true;d->have_sps=saw_sps;d->graph.identity.tested_profile=profile;
  {std::lock_guard<std::mutex> guard(d->events->mutex);++d->events->stats.pushed_units;d->events->stats.pushed_bytes+=size;}
  // buffer's local reference prevents its destructor until armed is set. From
  // here through its eventual destructor the original AU is native-owned.
  return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_decoder_output(rd_wd_decoder* d,rd_wd_decoded_frame* f,uint32_t* kind,rd_wd_error* e) {
  if(!d||!kind||!sized(f,sizeof(*f)))return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
  *kind=RD_WD_OUTPUT_NONE;
  if(d->sample)return result(e,RD_WD_BUSY,RD_WD_STAGE_RESOURCE);
  {
    std::lock_guard<std::mutex> guard(d->events->mutex);
    if(!d->events->output)return result(e,RD_WD_WOULD_BLOCK,RD_WD_STAGE_RESOURCE);
    --d->events->output;
  }
  MFT_OUTPUT_DATA_BUFFER output{};output.dwStreamID=d->graph.output;DWORD status=0;
  HRESULT hr=d->graph.transform->ProcessOutput(0,1,&output,&status);
  ComPtr<IMFSample> sample;sample.Attach(output.pSample);
  if(output.pEvents)output.pEvents->Release();
  if(hr==MF_E_TRANSFORM_STREAM_CHANGE) {
    if(FAILED(hr=output_type(d->graph.transform.Get(),d->graph.output,&d->graph.contract)))return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,hr);
    uint32_t profiles=0,configs=0;
    if(d->graph.contract.visible_width>d->max_width||d->graph.contract.visible_height>d->max_height)
      return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,MF_E_INVALIDMEDIATYPE);
    hr=decoder_profiles(d->presenter->devices,d->codec,d->graph.contract.width,d->graph.contract.height,&profiles,&configs);
    if(FAILED(hr))return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,hr);
    {std::lock_guard<std::mutex> guard(d->events->mutex);++d->events->stats.stream_changes;}
    *kind=RD_WD_OUTPUT_STREAM_CHANGE;return result(e);
  }
  if(FAILED(hr))return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_RESOURCE,hr);
  if(!sample||(output.dwStatus&MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE)==MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE) {
    std::lock_guard<std::mutex> guard(d->events->mutex);++d->events->stats.non_picture_outputs;return result(e);
  }
  DWORD buffers=0;
  if(FAILED(hr=sample->GetBufferCount(&buffers))||buffers!=1)return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,FAILED(hr)?hr:MF_E_UNSUPPORTED_D3D_TYPE);
  ComPtr<IMFMediaBuffer> buffer;ComPtr<IMFDXGIBuffer> dxgi;
  ComPtr<ID3D11Texture2D> texture;ComPtr<ID3D11Device> device;UINT subresource=0;
  if(FAILED(hr=sample->GetBufferByIndex(0,buffer.GetAddressOf()))||FAILED(hr=buffer.As(&dxgi))||
      FAILED(hr=dxgi->GetResource(IID_PPV_ARGS(texture.GetAddressOf())))||FAILED(hr=dxgi->GetSubresourceIndex(&subresource)))
    return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,hr);
  texture->GetDevice(device.GetAddressOf());D3D11_TEXTURE2D_DESC desc{};texture->GetDesc(&desc);
  if(device.Get()!=d->presenter->devices.device.Get()||desc.Format!=DXGI_FORMAT_NV12||desc.MipLevels!=1||
      !geometry(desc.Width,desc.Height)||!desc.ArraySize||desc.ArraySize>64||desc.SampleDesc.Count!=1||
      uint64_t(desc.Width)*desc.Height*3/2*desc.ArraySize>kMaxImageBytes||
      subresource>=desc.ArraySize||desc.CPUAccessFlags||desc.Usage!=D3D11_USAGE_DEFAULT)
    return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,MF_E_UNSUPPORTED_D3D_TYPE);
  ComPtr<IMFMediaType> actual;
  if(FAILED(hr=d->graph.transform->GetOutputCurrentType(d->graph.output,actual.GetAddressOf()))||
      FAILED(hr=contract_from(actual.Get(),&d->graph.contract)))return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,hr);
  const Contract& c=d->graph.contract;DXGI_COLOR_SPACE_TYPE color;
  if(!color_space(c,&color)||c.visible_width>d->max_width||c.visible_height>d->max_height||c.width>desc.Width||c.height>desc.Height)
    return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,MF_E_INVALIDMEDIATYPE);
  UINT32 interlaced=FALSE;
  hr=sample->GetUINT32(MFSampleExtension_Interlaced,&interlaced);
  if((FAILED(hr)&&hr!=MF_E_ATTRIBUTENOTFOUND)||interlaced)
    return result(e,RD_WD_UNSUPPORTED_FORMAT,RD_WD_STAGE_RESOURCE,FAILED(hr)?hr:MF_E_INVALIDMEDIATYPE);
  LONGLONG pts=0;if(FAILED(hr=sample->GetSampleTime(&pts)))return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_RESOURCE,hr);
  uint64_t ordinal;
  {std::lock_guard<std::mutex> guard(d->events->mutex);ordinal=++d->events->stats.decoded_pictures;d->events->stats.native_output_seen=1;}
  *f={sizeof(*f),desc.Width,desc.Height,subresource,c.width,c.height,c.aperture,c.left,c.top,
      c.visible_width,c.visible_height,c.primaries,c.transfer,c.matrix,c.range,c.chroma,d->generation,ordinal,pts,texture.Get(),device.Get()};
  {
    std::lock_guard<std::mutex> guard(d->events->mutex);
    d->events->stats.texture_array_size=desc.ArraySize;
    d->events->stats.texture_allocation_bytes=uint64_t(desc.Width)*desc.Height*3/2*desc.ArraySize;
    d->events->stats.last_output=*f;
    d->events->stats.last_output.d3d11_texture2d=nullptr;
    d->events->stats.last_output.d3d11_device=nullptr;
  }
  d->sample=sample;d->texture=texture;*kind=RD_WD_OUTPUT_PICTURE;return result(e);
}
void RD_WD_CALL rd_wd_decoder_release_output(rd_wd_decoder* d,const rd_wd_decoded_frame* f) {
  if(!d||!f)return;
  rd_wd_presenter::StateGuard guard(d->presenter);
  if(d->presenter->stats.unconfirmed)return;
  d->texture.Reset();d->sample.Reset();
}
rd_wd_status RD_WD_CALL rd_wd_decoder_drain(rd_wd_decoder* d,rd_wd_error* e) {
  if(!d)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_CLOSE);
  if(d->draining)return result(e);
  HRESULT hr=d->graph.transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM,d->graph.input);
  if(SUCCEEDED(hr))hr=d->graph.transform->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN,0);
  if(FAILED(hr))return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_CLOSE,hr);
  d->draining=true;return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_decoder_flush(rd_wd_decoder* d,rd_wd_error* e) {
  if(!d)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_CLOSE);
  if(d->flushed)return result(e);
  HRESULT hr=d->graph.transform->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH,0);
  if(FAILED(hr))return result(e,RD_WD_NATIVE_FAILURE,RD_WD_STAGE_CLOSE,hr);
  d->flushed=true;return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_decoder_snapshot(const rd_wd_decoder* d,rd_wd_decoder_stats* s,rd_wd_error* e) {
  if(!d||!sized(s,sizeof(*s)))return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_VALIDATE);
  std::lock_guard<std::mutex> guard(d->events->mutex);*s=d->events->stats;
  s->callback_in_flight=d->events->invoking;s->input_buffers_live=d->events->buffers.load();return result(e);
}
rd_wd_status RD_WD_CALL rd_wd_decoder_close(rd_wd_decoder* d,rd_wd_error* e) {
  if(!d)return result(e,RD_WD_INVALID_ARGUMENT,RD_WD_STAGE_CLOSE);
  HRESULT hr=d->cleanup();
  if(FAILED(hr)){d->presenter->uncertain(hr,RD_WD_STAGE_CLOSE);return result(e,RD_WD_RECLAMATION_UNCONFIRMED,RD_WD_STAGE_CLOSE,hr);}
  delete d;return result(e);
}
} // extern C
#endif // _WIN32: other targets never compile or link this translation unit.
