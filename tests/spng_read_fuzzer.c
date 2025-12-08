#include "spng.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* 极简版 Harness：只为了触发 spng.c 里的漏洞 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 1. 创建上下文
    spng_ctx *ctx = spng_ctx_new(0);
    if (ctx == NULL) return 0;

    // 2. 喂数据 (触发 spng.c 里的读取逻辑，可能触发 栈溢出)
    spng_set_png_buffer(ctx, data, size);

    // 3. 尝试解码 (触发 spng.c 里的解析逻辑，可能触发 空指针/格式化字符串)
    // 我们使用 SPNG_DECODE_PROGRESSIVE，这样即使数据不完整也会尝试处理
    spng_decode_image(ctx, NULL, 0, SPNG_FMT_RGBA8, SPNG_DECODE_PROGRESSIVE);

    // 4. 销毁 (必经之路：触发 spng.c 里的 Double Free 和 UAF)
    spng_ctx_free(ctx);

    return 0;
}
