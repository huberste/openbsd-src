/* $OpenBSD$ */
/*
 * Driver: Nuvoton NCT6116D Super-I/O GPIO on the DFI EHL253 / ED700-EHL.
 * Exposes the 8 onboard DIO pins (DIO0-7, the board LEDs) via the gpio(4)
 * framework.
 *
 * The pins are reached through the Super-I/O configuration index/data port
 * (0x2e or 0x4e), which wbsio(4) owns and keeps mapped.  nctgpio therefore
 * attaches as a child of wbsio(4) and shares wbsio's config-space handle
 * instead of mapping the port a second time (the ISA I/O extent forbids the
 * latter).
 *
 * Hardware facts were verified empirically on the target board (chip ID 0xD283
 * at LPC config port 0x4E; register map below). Register semantics on THIS
 * chip:
 *   - direction register (LDN7 base+0):  bit 0 = OUTPUT, 1 = INPUT   (note:
 *     inverted vs. some docs -- confirmed by measurement)
 *   - data register      (LDN7 base+1):  bit = pin level (1 = high, 0 = low)
 *
 * DIO -> Nuvoton pin map (NON-contiguous, measured):
 *   DIO0 GPIO40  dir 0xF0 data 0xF1 bit0      DIO4 GPIO44  0xF0/0xF1 bit4
 *   DIO1 GPIO41  0xF0/0xF1 bit1              DIO5 GPIO47  0xF0/0xF1 bit7
 *   DIO2 GPIO42  0xF0/0xF1 bit2              DIO6 GPIO33  0xEC/0xED bit3
 *   DIO3 GPIO43  0xF0/0xF1 bit3              DIO7 GPIO37  0xEC/0xED bit7
 * Physical order is left-to-right DIO0..DIO7. Pins idle HIGH (LED on).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/gpio.h>

#include <machine/bus.h>

#include <dev/isa/isavar.h>
#include <dev/isa/wbsiovar.h>
#include <dev/gpio/gpiovar.h>

/* Super-I/O index/data window (2 bytes at the config base, 0x2E or 0x4E). */
#define NCT_IOSIZE		2
#define NCT_INDEX		0
#define NCT_DATA		1

#define NCT_ENTER_KEY		0x87	/* write twice to INDEX to unlock */
#define NCT_EXIT_KEY		0xaa	/* write once to INDEX to lock */

#define NCT_REG_LDN		0x07	/* logical-device select */
#define NCT_LDN_GPIO		0x07	/* GPIO logical device */
#define NCT_REG_CHIPID_HI	0x20
#define NCT_REG_CHIPID_LO	0x21
#define NCT_CHIPID_MASK		0xfff0	/* low nibble = revision */
#define NCT_CHIPID_6116		0xd280	/* NCT6116D family */

#define NCT_NPINS		8

struct nctgpio_pinmap { uint8_t dir, data, bit; };
static const struct nctgpio_pinmap nctgpio_map[NCT_NPINS] = {
	{ 0xf0, 0xf1, 0 },	/* DIO0 / GPIO40 */
	{ 0xf0, 0xf1, 1 },	/* DIO1 / GPIO41 */
	{ 0xf0, 0xf1, 2 },	/* DIO2 / GPIO42 */
	{ 0xf0, 0xf1, 3 },	/* DIO3 / GPIO43 */
	{ 0xf0, 0xf1, 4 },	/* DIO4 / GPIO44 */
	{ 0xf0, 0xf1, 7 },	/* DIO5 / GPIO47 */
	{ 0xec, 0xed, 3 },	/* DIO6 / GPIO33 */
	{ 0xec, 0xed, 7 },	/* DIO7 / GPIO37 */
};

struct nctgpio_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;		/* shared with wbsio(4) */
	struct gpio_chipset_tag	sc_gc;
	gpio_pin_t		sc_pins[NCT_NPINS];
};

int	nctgpio_match(struct device *, void *, void *);
void	nctgpio_attach(struct device *, struct device *, void *);
int	nctgpio_pin_read(void *, int);
void	nctgpio_pin_write(void *, int, int);
void	nctgpio_pin_ctl(void *, int, int);

const struct cfattach nctgpio_ca = {
	sizeof(struct nctgpio_softc), nctgpio_match, nctgpio_attach
};
struct cfdriver nctgpio_cd = { NULL, "nctgpio", DV_DULL };

/* --- Super-I/O config-space primitives (assume caller holds splhigh) --- */
static __inline void
nct_enter(struct nctgpio_softc *sc)
{
	bus_space_write_1(sc->sc_iot, sc->sc_ioh, NCT_INDEX, NCT_ENTER_KEY);
	bus_space_write_1(sc->sc_iot, sc->sc_ioh, NCT_INDEX, NCT_ENTER_KEY);
	/* land on the GPIO logical device for every transaction */
	bus_space_write_1(sc->sc_iot, sc->sc_ioh, NCT_INDEX, NCT_REG_LDN);
	bus_space_write_1(sc->sc_iot, sc->sc_ioh, NCT_DATA,  NCT_LDN_GPIO);
}
static __inline void
nct_exit(struct nctgpio_softc *sc)
{
	bus_space_write_1(sc->sc_iot, sc->sc_ioh, NCT_INDEX, NCT_EXIT_KEY);
}
static __inline uint8_t
nct_read(struct nctgpio_softc *sc, uint8_t reg)
{
	bus_space_write_1(sc->sc_iot, sc->sc_ioh, NCT_INDEX, reg);
	return bus_space_read_1(sc->sc_iot, sc->sc_ioh, NCT_DATA);
}
static __inline void
nct_write(struct nctgpio_softc *sc, uint8_t reg, uint8_t val)
{
	bus_space_write_1(sc->sc_iot, sc->sc_ioh, NCT_INDEX, reg);
	bus_space_write_1(sc->sc_iot, sc->sc_ioh, NCT_DATA,  val);
}

int
nctgpio_match(struct device *parent, void *match, void *aux)
{
	struct isa_attach_args *ia = aux;
	uint16_t id;
	int s;

	/* Only the GPIO offer from wbsio(4) carries this sentinel. */
	if (ia->ia_aux != (void *)wbsio_gpio_tag)
		return 0;

	/* Confirm the chip through wbsio's shared config-space handle. */
	s = splhigh();
	bus_space_write_1(ia->ia_iot, ia->ia_ioh, NCT_INDEX, NCT_ENTER_KEY);
	bus_space_write_1(ia->ia_iot, ia->ia_ioh, NCT_INDEX, NCT_ENTER_KEY);
	bus_space_write_1(ia->ia_iot, ia->ia_ioh, NCT_INDEX, NCT_REG_CHIPID_HI);
	id  = bus_space_read_1(ia->ia_iot, ia->ia_ioh, NCT_DATA) << 8;
	bus_space_write_1(ia->ia_iot, ia->ia_ioh, NCT_INDEX, NCT_REG_CHIPID_LO);
	id |= bus_space_read_1(ia->ia_iot, ia->ia_ioh, NCT_DATA);
	bus_space_write_1(ia->ia_iot, ia->ia_ioh, NCT_INDEX, NCT_EXIT_KEY);
	splx(s);

	if ((id & NCT_CHIPID_MASK) != NCT_CHIPID_6116)
		return 0;
	ia->ia_iosize = NCT_IOSIZE;
	return 1;
}

void
nctgpio_attach(struct device *parent, struct device *self, void *aux)
{
	struct nctgpio_softc *sc = (struct nctgpio_softc *)self;
	struct isa_attach_args *ia = aux;
	struct gpiobus_attach_args gba;
	int i, s;

	/* Share wbsio(4)'s already-mapped config-space handle; do not map. */
	sc->sc_iot = ia->ia_iot;
	sc->sc_ioh = ia->ia_ioh;

	s = splhigh();
	nct_enter(sc);
	for (i = 0; i < NCT_NPINS; i++) {
		uint8_t dir = nct_read(sc, nctgpio_map[i].dir);
		uint8_t dat = nct_read(sc, nctgpio_map[i].data);
		uint8_t m   = 1 << nctgpio_map[i].bit;

		sc->sc_pins[i].pin_num   = i;
		sc->sc_pins[i].pin_caps  = GPIO_PIN_INPUT | GPIO_PIN_OUTPUT;
		sc->sc_pins[i].pin_flags =
		    (dir & m) ? GPIO_PIN_INPUT : GPIO_PIN_OUTPUT;
		sc->sc_pins[i].pin_state =
		    (dat & m) ? GPIO_PIN_HIGH : GPIO_PIN_LOW;
	}
	nct_exit(sc);
	splx(s);

	sc->sc_gc.gp_cookie    = sc;
	sc->sc_gc.gp_pin_read  = nctgpio_pin_read;
	sc->sc_gc.gp_pin_write = nctgpio_pin_write;
	sc->sc_gc.gp_pin_ctl   = nctgpio_pin_ctl;

	gba.gba_name  = "gpio";
	gba.gba_gc    = &sc->sc_gc;
	gba.gba_pins  = sc->sc_pins;
	gba.gba_npins = NCT_NPINS;

	printf(": NCT6116D GPIO, %d pins (DIO0-7)\n", NCT_NPINS);
	config_found(self, &gba, gpiobus_print);
}

int
nctgpio_pin_read(void *arg, int pin)
{
	struct nctgpio_softc *sc = arg;
	uint8_t v;
	int s;

	if (pin < 0 || pin >= NCT_NPINS)
		return GPIO_PIN_LOW;
	s = splhigh();
	nct_enter(sc);
	v = nct_read(sc, nctgpio_map[pin].data);
	nct_exit(sc);
	splx(s);
	return (v & (1 << nctgpio_map[pin].bit)) ? GPIO_PIN_HIGH : GPIO_PIN_LOW;
}

void
nctgpio_pin_write(void *arg, int pin, int value)
{
	struct nctgpio_softc *sc = arg;
	uint8_t v, m;
	int s;

	if (pin < 0 || pin >= NCT_NPINS)
		return;
	m = 1 << nctgpio_map[pin].bit;
	s = splhigh();
	nct_enter(sc);
	v = nct_read(sc, nctgpio_map[pin].data);
	if (value == GPIO_PIN_HIGH)
		v |= m;
	else
		v &= ~m;
	nct_write(sc, nctgpio_map[pin].data, v);
	nct_exit(sc);
	splx(s);
}

void
nctgpio_pin_ctl(void *arg, int pin, int flags)
{
	struct nctgpio_softc *sc = arg;
	uint8_t v, m;
	int s;

	if (pin < 0 || pin >= NCT_NPINS)
		return;
	m = 1 << nctgpio_map[pin].bit;
	s = splhigh();
	nct_enter(sc);
	v = nct_read(sc, nctgpio_map[pin].dir);
	if (flags & GPIO_PIN_INPUT)
		v |= m;		/* 1 = input  (measured polarity) */
	else if (flags & GPIO_PIN_OUTPUT)
		v &= ~m;	/* 0 = output */
	nct_write(sc, nctgpio_map[pin].dir, v);
	nct_exit(sc);
	splx(s);
}
