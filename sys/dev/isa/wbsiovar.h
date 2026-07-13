/*	$OpenBSD$	*/
/*
 * Copyright (c) 2026 Stefan Huber
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Interface between wbsio(4) and its children.
 *
 * wbsio(4) keeps the Super-I/O configuration index/data port mapped for its
 * whole lifetime.  Children whose registers live behind that same port (e.g.
 * nctgpio(4)) share the mapping through the standard isa_attach_args: wbsio
 * fills ia_iot/ia_ioh with the live config-port tag and handle, sets
 * ia_iobase/ia_iosize to that port, and stores the sentinel below in ia_aux.
 *
 * wbsio_gpio_tag is compared by identity only and is never dereferenced, so it
 * is safe for a sibling's match routine to receive an offer meant for another
 * child (the hardware-monitor offer stores a device id in ia_aux instead).
 */

extern const char wbsio_gpio_tag[];
