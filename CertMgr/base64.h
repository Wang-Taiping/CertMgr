#pragma once

#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

	size_t base64_encode_calc_buffer(size_t data_bytes);
	size_t base64_decode_calc_buffer(size_t data_bytes); // return -1 error

	size_t base64_encode(const void* src_data, size_t src_bytes, void* dst_buffer, size_t dst_bytes);
	size_t base64_decode(const void* src_data, size_t src_bytes, void* dst_buffer, size_t dst_bytes); // return -1 error

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // !BASE64_H
