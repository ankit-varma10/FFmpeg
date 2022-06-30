#include <stdbool.h>

#include "libavutil/avassert.h"
#include "libavutil/bswap.h"
#include "libavutil/crc.h"
#include "libavutil/dict.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/mathematics.h"
#include "libavutil/opt.h"

#include "libavcodec/ac3_parser_internal.h"
#include "libavcodec/startcode.h"

#include "avc.h"
#include "avformat.h"
#include "avio_internal.h"
#include "internal.h"

#define ADTS_SYNC_WORD 0xF0FF

#define RUSH_FIELD_LENGTH_SIZE 8
#define RUSH_FIELD_ID_SIZE 8
#define RUSH_FIELD_TYPE_SIZE 1
#define RUSH_FIELD_VERSION_SIZE 1
#define RUSH_FIELD_VIDEO_TIMESCALE_SIZE 2
#define RUSH_FIELD_AUDIO_TIMESCALE_SIZE 2
#define RUSH_FIELD_BROADCAST_ID_SIZE 8
#define RUSH_FIELD_CODEC_SIZE 1
#define RUSH_FIELD_PTS_SIZE 8
#define RUSH_FIELD_DTS_SIZE 8
#define RUSH_FIELD_TIMESTAMP_SIZE 8
#define RUSH_FIELD_TRACK_ID 1
#define RUSH_FIELD_REQUIRED_FRAME_OFFSET 2

#define CONNECT_FRAME_HEADER_SIZE \
    (RUSH_FIELD_LENGTH_SIZE + \
     RUSH_FIELD_ID_SIZE + \
     RUSH_FIELD_TYPE_SIZE + \
     RUSH_FIELD_VERSION_SIZE + \
     RUSH_FIELD_VIDEO_TIMESCALE_SIZE + \
     RUSH_FIELD_AUDIO_TIMESCALE_SIZE + \
     RUSH_FIELD_BROADCAST_ID_SIZE)

#define VIDEO_FRAME_HEADER_SIZE \
    (RUSH_FIELD_LENGTH_SIZE + \
     RUSH_FIELD_ID_SIZE + \
     RUSH_FIELD_TYPE_SIZE + \
     RUSH_FIELD_CODEC_SIZE + \
     RUSH_FIELD_PTS_SIZE + \
     RUSH_FIELD_DTS_SIZE + \
     RUSH_FIELD_TRACK_ID + \
     RUSH_FIELD_REQUIRED_FRAME_OFFSET)

#define AUDIO_FRAME_HEADER_SIZE \
    (RUSH_FIELD_LENGTH_SIZE + \
     RUSH_FIELD_ID_SIZE + \
     RUSH_FIELD_TYPE_SIZE + \
     RUSH_FIELD_CODEC_SIZE + \
     RUSH_FIELD_TIMESTAMP_SIZE + \
     RUSH_FIELD_TRACK_ID)

#define END_OF_STREAM_HEADER_SIZE 0x11

static const uint16_t MAX_REQUIRED_OFFSET_VALUE = 0xFFFF;

typedef struct FbvpContext {
    const AVClass *av_class;
    uint16_t audio_timescale;
    uint16_t video_timescale;
    uint64_t frame_id;
    uint8_t count_audio_streams;
    uint8_t count_video_streams;
    uint32_t *index_to_last_keyframe_id;
    uint64_t *index_to_track_id ;
    AVFormatContext *amux;
    AVPacket *pkt;
    bool has_written_codec_specific_data;

} FbvpContext;

typedef enum {
    FRAME_TYPE_CONNECT          = 0x0,
    FRAME_TYPE_VIDEO_WITH_TRACK = 0xD,
    FRAME_TYPE_AUDIO_WITH_TRACK = 0xE,
    FRAME_TYPE_END_OF_STREAM    = 0x4,
} FrameType;

typedef enum {
    NAL_UNSPECIFIED     = 0,
    NAL_SLICE           = 1,
    NAL_IDR_SLICE       = 5,
    NAL_SPS             = 7,
    NAL_PPS             = 8,
} NALUHeader;

typedef enum {
    VIDEO_CODEC_H264 = 0x1,
    VIDEO_CODEC_H265 = 0x2,
    VIDEO_CODEC_VP8  = 0x3,
    VIDEO_CODEC_VP9  = 0x4,
} VideoCodec;

typedef enum {
    AUDIO_CODEC_ACC  = 0x1,
    AUDIO_CODEC_OPUS = 0x2,
} AudioCodec;

static int rush_init(AVFormatContext *s)
{
    FbvpContext *ctx = (FbvpContext*)s->priv_data;
    ctx->audio_timescale = 0;
    ctx->video_timescale = 0;
    ctx->frame_id = 1;
    ctx->count_audio_streams = 0;
    ctx->count_video_streams = 0;
    ctx->index_to_track_id = NULL;
    ctx->index_to_last_keyframe_id = NULL;
    ctx->pkt = ffformatcontext(s)->pkt;
    ctx->has_written_codec_specific_data = false;
    return 0;
}

static void rush_deinit(AVFormatContext *s)
{
    FbvpContext *ctx = (FbvpContext*)s->priv_data;
    if (ctx->index_to_track_id) {
        av_free(ctx->index_to_track_id);
    }
    if (ctx->index_to_last_keyframe_id) {
        av_free(ctx->index_to_last_keyframe_id);
    }
    return;
}

static int parse_nal_units(AVIOContext *pb, uint8_t *buf_in, int size)
{
    uint8_t *start = buf_in;
    const uint8_t *end = buf_in + size;
    int i, j;

    uint8_t nalu_prefix_length = 0;
    uint8_t num_nalus = 0;
    uint32_t nalu_length = 0;

    start += 4; // skip start code

    nalu_prefix_length = (AV_RB8(start) & 0x3) + 1;
    if (nalu_prefix_length != 4) {
        av_log(NULL, AV_LOG_ERROR, "Only 4 bytes prefixed NALU are supported\n");
        return AVERROR(EINVAL);
    }
    start += 1; // move size(nalu_prefix_length)


    for (i = 0; i < 2; ++i) {
        num_nalus = AV_RB8(start) & 0x1F;
        start += 1; // move size(num_nalus)
        for (j = 0; j < num_nalus; ++j) {
            nalu_length = AV_RB16(start);
            if (start + nalu_length > end) {
                av_log(NULL, AV_LOG_ERROR, "Cannot parse data. NALU field not valid\n");
                return AVERROR(ERANGE);
            }
            start += 2; // move size(nalu_length)
            avio_wb32(pb, nalu_length);
            avio_write(pb, start, nalu_length);
            start += nalu_length;
        }
    }
    return 0;
}

static int process_extradata(uint8_t *buf_in,
                             int buf_in_size,
                             uint8_t **buf_out,
                             int *buf_out_size)
{
    AVIOContext *pb;
    int ret = avio_open_dyn_buf(&pb);
    if (ret < 0) {
        return ret;
    }
    parse_nal_units(pb, buf_in, buf_in_size);
    *buf_out_size = avio_close_dyn_buf(pb, buf_out);
    return 0;
}

static bool is_codec_supported(enum AVMediaType mediaType, enum AVCodecID codec)
{
    if (mediaType == AVMEDIA_TYPE_VIDEO) {
        return codec == AV_CODEC_ID_H264 ||
               codec == AV_CODEC_ID_VP8 ||
               codec == AV_CODEC_ID_VP9;
    }
    if (mediaType == AVMEDIA_TYPE_AUDIO) {
        return codec == AV_CODEC_ID_AAC;
    }
    return false;
}

static int should_process_extra_data(const uint8_t *data,
                                     int data_size,
                                     bool *has_written_codec_specific_data,
                                     bool *is_key_frame,
                                     bool *should_process)
{
    const uint8_t *start = data;
    const uint8_t *end = data + data_size;

    int nalu_length = 0;
    bool sps = false, pps = false, idr = false;

    while (start < end) {
        if (start + sizeof(nalu_length) > end) {
            av_log(NULL, AV_LOG_ERROR, "Invalid NALU length\n");
            return AVERROR_INVALIDDATA;
        }
        nalu_length = AV_RB32(start);
        if ((start + nalu_length) > end) {
            av_log(NULL, AV_LOG_ERROR, "Invalid NALU length\n");
            return AVERROR_INVALIDDATA;
        }
        start += sizeof(nalu_length);

        switch (start[0] & 0x1F) {
            case NAL_SPS:
                sps = true;
                break;
            case NAL_PPS:
                pps = true;
               break;
            case NAL_IDR_SLICE:
               idr = true;
              break;
            default:
              break;
        }
        start += nalu_length;

        if (sps && pps && idr) {
            break;
        }
    }

    *is_key_frame = idr;

    // sps and pps are containted in-band, don't process extradata
    if (sps || pps) {
        *should_process = false;
        return 0;
    }

    // key frame present or processsing the first frame(?)
    if (*is_key_frame || !*has_written_codec_specific_data) {
        *has_written_codec_specific_data = true;
        *should_process = true;
        return 0;
    }

    return 0;
}

static int preprocess_h264(uint8_t *data,
                           int data_size,
                           uint8_t *extradata,
                           int extradata_size,
                           uint8_t **buf_out,
                           int *buf_out_size,
                           bool *has_written_codec_specific_data,
                           bool *is_key_frame)
{
    int error = 0;
    bool should_process = false;
    if (!extradata) {
        return 0;
    }
    error = should_process_extra_data(data,
                                      data_size,
                                      has_written_codec_specific_data,
                                      is_key_frame,
                                      &should_process);
    if (error) {
        return error;
    }
    if (!should_process) {
        return 0;
    }
    error = process_extradata(extradata,
                              extradata_size,
                              buf_out,
                              buf_out_size);
    if (error) {
        return error;
    }
    return 0;
}

static int preprocess_aac_data(AVFormatContext *s,
                               AVPacket *pkt,
                               FbvpContext *ctx)
{
    int ret =0;
    int size = 0;
    AVPacket *pkt2 = ctx->pkt;
    uint8_t *data = NULL;
    if ((AV_RB16(pkt->data) & ADTS_SYNC_WORD) == ADTS_SYNC_WORD) {
        return 0;
    }
    if (!ctx->amux) {
        av_log(s, AV_LOG_ERROR, "AAC bitstream not in ADTS format "
                                "and extradata missing\n");
        return AVERROR(EINVAL);
    }

    if (pkt2) {
        av_packet_unref(pkt2);
    }

    pkt2->data = pkt->data;
    pkt2->size = pkt->size;
    pkt2->dts = av_rescale_q(pkt->dts,
                            s->streams[pkt->stream_index]->time_base,
                            ctx->amux->streams[0]->time_base);

    ret = avio_open_dyn_buf(&ctx->amux->pb);
    if (ret < 0) {
        return ret;
    }
    ret = av_write_frame(ctx->amux, pkt2);
    if (ret < 0) {
        ffio_free_dyn_buf(&ctx->amux->pb);
        return ret;
    }
    size = avio_close_dyn_buf(ctx->amux->pb, &data);
    ctx->amux->pb = NULL;
    pkt->data = data;
    pkt->size = size;
    return 0;
}

static int rush_write_audio_packet(AVFormatContext *s, AVPacket *pkt)
{
    FbvpContext *ctx = (FbvpContext*)s->priv_data;
    AVIOContext *pb = s->pb;
    AVStream *st = s->streams[pkt->stream_index];
    AVCodecParameters *codecpar = st->codecpar;
    int ret = 0;

    const enum AVCodecID codec = codecpar->codec_id;

    if (codec != AV_CODEC_ID_AAC) {
        av_log(s, AV_LOG_ERROR, "Unhandled format %d\n", codec);
        return AVERROR(EINVAL);
    }

    if (pkt->size < 2) {
        av_log(s, AV_LOG_ERROR, "AAC packet too short\n");
        return AVERROR(EINVAL);
    }

    ret = preprocess_aac_data(s, pkt, ctx);
    if (ret) {
        av_log(s, AV_LOG_ERROR, "Could not proces aac data %d\n", ret);
    }

    avio_wl64(pb, AUDIO_FRAME_HEADER_SIZE + pkt->size);
    avio_wl64(pb, ctx->frame_id);
    avio_w8(pb, FRAME_TYPE_AUDIO_WITH_TRACK);
    avio_w8(pb, 0x1);
    avio_wl64(pb, pkt->dts);
    avio_w8(pb, ctx->index_to_track_id[pkt->stream_index]);
    avio_write(pb, pkt->data, pkt->size);

    ctx->frame_id += 1;

    return 0;
}

static int rush_write_video_packet(AVFormatContext *s, AVPacket *pkt)
{
    FbvpContext *ctx = (FbvpContext*)s->priv_data;
    AVIOContext *pb = s->pb;
    AVStream *st = s->streams[pkt->stream_index];
    AVCodecParameters *codecpar = st->codecpar;

    uint32_t required_frame_offset = 0;
    uint64_t last_key_frame_id = 0;
    bool is_key_frame = false;

    const enum AVCodecID codec = codecpar->codec_id;
    const uint64_t frame_id = ctx->frame_id;

    uint8_t *extradata_nalus = NULL;
    int extradata_nalus_size = 0;

    int ret = 0;

    if (!is_codec_supported(AVMEDIA_TYPE_VIDEO, codec)) {
        av_log(s, AV_LOG_ERROR, "Unhandled format %d\n", codec);
        return AVERROR(EINVAL);
    }


    if (codec == AV_CODEC_ID_H264) {
        ret = preprocess_h264(pkt->data,
                              pkt->size,
                              codecpar->extradata,
                              codecpar->extradata_size,
                              &extradata_nalus,
                              &extradata_nalus_size,
                              &ctx->has_written_codec_specific_data,
                              &is_key_frame);
        if (ret) {
            return ret;
        }
    }
    else if (codec == AV_CODEC_ID_H265) {

    }
    else if(codec == AV_CODEC_ID_VP8 || codec == AV_CODEC_ID_VP9) {
        is_key_frame = pkt->flags & AV_PKT_FLAG_KEY;
    }

    if (is_key_frame) {
       required_frame_offset = 0;
       ctx->index_to_last_keyframe_id[pkt->stream_index] = frame_id;
    }
    else {
       last_key_frame_id = ctx->index_to_last_keyframe_id[pkt->stream_index];
       if (!last_key_frame_id) {
           av_log(s, AV_LOG_ERROR, "Frame without a preceding key frame\n");
           return AVERROR(EINVAL);
       }
       required_frame_offset = frame_id - last_key_frame_id;
       if (required_frame_offset >= MAX_REQUIRED_OFFSET_VALUE) {
           av_log(s, AV_LOG_ERROR, "Required frame offset larger than maximum allowed\n");
           return AVERROR(EINVAL);
       }
    }

    avio_wl64(pb, VIDEO_FRAME_HEADER_SIZE + pkt->size + extradata_nalus_size);
    avio_wl64(pb, frame_id);
    avio_w8(pb, FRAME_TYPE_VIDEO_WITH_TRACK);
    avio_w8(pb, 0x1);
    avio_wl64(pb, pkt->pts);
    avio_wl64(pb, pkt->dts);
    avio_w8(pb, ctx->index_to_track_id[pkt->stream_index]);
    avio_wl16(pb, required_frame_offset);

    ctx->frame_id += 1;

    if (extradata_nalus_size) {
        avio_write(pb, extradata_nalus, extradata_nalus_size);
    }
    avio_write(pb, pkt->data, pkt->size);

    return 0;
}

static int rush_write_packet(AVFormatContext *s, AVPacket *pkt)
{
    AVStream *st = s->streams[pkt->stream_index];
    AVCodecParameters *codecpar = st->codecpar;
    if (codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
        rush_write_audio_packet(s, pkt);
    }
    else if(codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
       rush_write_video_packet(s, pkt);
    }
    else {
        av_log(s, AV_LOG_ERROR, "Unhandled format %d\n", codecpar->codec_type);
    }
    return 0;
}


static int rush_write_header(AVFormatContext *s)
{
    FbvpContext *ctx = (FbvpContext*)s->priv_data;
    AVIOContext *pb = s->pb;
    int i, ret = 0;

    AVDictionaryEntry *tag = NULL;

    // payload test
    tag = av_dict_get(s->metadata, "connectpayload", NULL, 0);
    av_log(s, AV_LOG_ERROR, "connectpayload %s\n", tag->value);
    // payload test

    ctx->index_to_track_id = av_calloc(s->nb_streams, sizeof(uint32_t));
    if (!ctx->index_to_track_id) {
        return AVERROR(ENOMEM);
    }
    memset(ctx->index_to_track_id, 0, s->nb_streams * sizeof(uint32_t));

    ctx->index_to_last_keyframe_id = av_calloc(s->nb_streams, sizeof(uint64_t));
    if (!ctx->index_to_last_keyframe_id) {
        return AVERROR(ENOMEM);
    }
    memset(ctx->index_to_last_keyframe_id, 0, s->nb_streams * sizeof(uint32_t));

    for (i = 0; i < s->nb_streams; ++i) {
        AVStream *st = s->streams[i];
        const enum AVMediaType media_type = st->codecpar->codec_type;
        const enum AVCodecID codec = st->codecpar->codec_id;
        if (media_type == AVMEDIA_TYPE_AUDIO && is_codec_supported(media_type, codec)) {
            ctx->index_to_track_id[i] = ctx->count_audio_streams++;

            if (ctx->audio_timescale &&
                ctx->audio_timescale != st->codecpar->sample_rate) {
                av_log(s, AV_LOG_ERROR, "Two audio streams with different time scales\n");
                return AVERROR(EINVAL);
            }
            ctx->audio_timescale = st->codecpar->sample_rate;
            avpriv_set_pts_info(s->streams[i], 64, 1, ctx->audio_timescale);

            if(st->codecpar->codec_id == AV_CODEC_ID_AAC && st->codecpar->extradata) {
                ctx->amux = avformat_alloc_context();
                if (!ctx->amux) {
                    return AVERROR(ENOMEM);
                }
                ctx->amux->oformat =  av_guess_format("adts", NULL, NULL);
                if (!ctx->amux->oformat) {
                    return AVERROR(EINVAL);
                }
                AVStream *audio_stream = avformat_new_stream(ctx->amux, NULL);
                if (!audio_stream) {
                        return AVERROR(ENOMEM);
                    }
                    ret = avcodec_parameters_copy(audio_stream->codecpar, st->codecpar);
                    if (ret < 0) {
                        return ret;
                    }
                    audio_stream->time_base = st->time_base;
                    ret = avformat_write_header(ctx->amux, NULL);
                    if (ret < 0) {
                        return ret;
                    }
                }
            }
            else if (media_type == AVMEDIA_TYPE_VIDEO && is_codec_supported(media_type, codec)) {
                ctx->index_to_track_id[i] = ctx->count_video_streams++;
                if (ctx->video_timescale &&
                    ctx->video_timescale != st->time_base.den) {
                    av_log(s, AV_LOG_ERROR, "Two video streams with different time scales\n");
                    return AVERROR(EINVAL);
                }
                ctx->video_timescale = st->time_base.den;
                avpriv_set_pts_info(s->streams[i], 64, 1, ctx->video_timescale);
            }
            else {
                av_log(s, AV_LOG_ERROR, "Unhandled format %d\n", media_type);
                return AVERROR(EINVAL);
            }
        }

        avio_wl64(pb, CONNECT_FRAME_HEADER_SIZE);
        avio_wl64(pb, ctx->frame_id);
        avio_w8(pb, FRAME_TYPE_CONNECT);
        avio_w8(pb, 0x1);
        avio_wl16(pb, ctx->video_timescale);
        avio_wl16(pb, ctx->audio_timescale);
        avio_wl64(pb, 0x1); // broadcast-id

        ctx->frame_id += 1;

        return 0;
    }

    static int rush_write_trailer(AVFormatContext *s)
    {
        FbvpContext *ctx = (FbvpContext*)s->priv_data;
        AVIOContext *pb = s->pb;
        avio_wl64(pb, END_OF_STREAM_HEADER_SIZE);
        avio_wl64(pb, ctx->frame_id);
        avio_w8(pb, FRAME_TYPE_END_OF_STREAM);
        return 0;
    }

    const AVOutputFormat ff_rush_muxer = {
        .name = "rush",
        .long_name = "FB Video Protocol/1",
        .extensions = "rush",
        .priv_data_size = sizeof(FbvpContext),
    .audio_codec = AV_CODEC_ID_AAC,
    .video_codec = AV_CODEC_ID_H264,
    .init = rush_init,
    .deinit = rush_deinit,
    .write_packet = rush_write_packet,
    .write_header = rush_write_header,
    .write_trailer = rush_write_trailer,
};
