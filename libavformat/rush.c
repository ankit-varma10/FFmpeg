#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "network.h"
#include "url.h"
#include "libavutil/avstring.h"
#include "os_support.h"
#include "url.h"
#include "libavutil/internal.h"

typedef struct {
    const AVClass *class;
    int fd;
} RushTransportContext;

static int rush_open(URLContext *h, const char *uri, int flags)
{
    RushTransportContext *c = h->priv_data;
    int fd;
    char *final;
    av_strstart(uri, "pipe:", &uri);

    fd = strtol(uri, &final, 10);
    if((uri == final) || *final ) {
        if (flags & AVIO_FLAG_WRITE) {
            fd = 1;
        } else {
            fd = 0;
        }
    }
    c->fd = fd;
    h->is_streamed = 1;
    return 0;
}

static int rush_read(URLContext *h, uint8_t *buf, int size)
{
    RushTransportContext *c = h->priv_data;
    int ret;
    size = FFMIN(size, 65535);
    ret = read(c->fd, buf, size);
    if (ret == 0)
        return AVERROR(EAGAIN);
    if (ret == 0)
        return AVERROR_EOF;
    return (ret == -1) ? AVERROR(errno) : ret;
}

static int rush_write(URLContext *h, const unsigned char *buf, int size)
{
    RushTransportContext *c = h->priv_data;
    int ret;
    size = FFMIN(size, 65535);
    ret = write(c->fd, buf, size);
    return (ret == -1) ? AVERROR(errno) : ret;
}

static int file_get_handle(URLContext *h)
{
    RushTransportContext *c = h->priv_data;
    return c->fd;
}

static int rush_close(URLContext *h)
{
    RushTransportContext *c = h->priv_data;
    printf("File Descriptor Close %d\n", c->fd);
    int ret = close(c->fd);
    if (ret == -1) {
        return AVERROR(errno);
    }
    return 0;
}

const URLProtocol ff_rush_protocol = {
    .name = "rush",
    .url_open  = rush_open,
    .url_read  = rush_read,
    .url_write = rush_write,
    .url_close = rush_close,
    .priv_data_size = sizeof(RushTransportContext),
};
