# One Stroke — Forensics Writeup

**Challenge:** One Stroke  
**Category:** Forensics  
**Author:** @yuneko.dev (Ellie)  
**Points:** 500

> This writeup was prepared with the help of AI.

## Challenge Description

> This monochrome image doesn't seem to contain anything useful. Or perhaps you're just looking at it the wrong way.

**Flag format:**

```text
LYKNCTF{<uuid>}
```

---

## Author's Writeup

To be honest, I'm not even sure how to write a proper writeup for this challenge. The idea actually came to me after I saw an R18 image on Facebook.

Tool used: https://xiaofanqiehunxiao.com/

I'll quote the writeup from a player who successfully solved this challenge.

<details>
<summary><b><a href="https://discord.com/users/1014709876418682910">Clay's Writeup</a></b>
(Click to expand/collapse)</summary>

## Initial Thoughts

The challenge gave me a single JPEG image that looked like random black strokes scattered over a white background.

At first glance, it genuinely looked useless.

The image dimensions were:

```text
1386 × 424
```

The first thing that caught my attention was the wording:

> “Perhaps you're just looking at it the wrong way.”

That sounded like a strong hint toward some kind of image transformation. My initial possibilities included:

- rotation or flipping
- stereogram/autostereogram
- hidden color channels
- bit planes
- frequency-domain encoding
- some kind of geometric remapping

Unfortunately, this led me into quite a few rabbit holes before I found the actual intended method.

---

## The First Useful Hint

Then the challenge author released this hint:

> **It's just a pixel permutation.**

This immediately killed most of my previous hypotheses.

That meant:

- no hidden payload
- no DCT steganography
- no secret LSB stream
- no extra data

The original image was still there.

The pixels had simply been rearranged.

That was the first major breakthrough.

---

## The Second Hint

The next hint was:

> **Nearby pixels tend to stay nearby. Try following a path instead of rows.**

This was much more specific.

The phrase:

> “Nearby pixels tend to stay nearby”

strongly suggested a **space-filling curve**.

The obvious candidate was a Hilbert curve because one of its most important properties is locality preservation: points close together in one-dimensional Hilbert order tend to remain spatially close in two dimensions.

The challenge title also suddenly made sense:

> **One Stroke**

A Hilbert-like curve traverses the entire image as one continuous path.

---

## My First Hilbert Mistake

I initially made a wrong assumption.

A normal Hilbert curve works naturally on square grids whose dimensions are powers of two, for example:

```text
256 × 256
512 × 512
1024 × 1024
```

But the challenge image was:

```text
1386 × 424
```

So I first tried things like:

- padding into a larger power-of-two square
- dividing into square tiles
- applying Hilbert traversal tile by tile
- mapping between row-major and Hilbert-major layouts

These produced interesting-looking output, but no flag.

The important realization was that I did **not** need to force the image into a square.

I needed a Hilbert-style path that fills an arbitrary rectangle.

---

## Rectangular Gilbert Curve

For that, I used a generalized rectangular Hilbert-style traversal, commonly called a **Gilbert curve**.

The path covers every pixel exactly once while still preserving locality.

Conceptually:

```text
(x0, y0)
(x1, y1)
(x2, y2)
...
(xN-1, yN-1)
```

where:

```text
N = width × height
```

For this image:

```text
N = 1386 × 424
  = 587664
```

So now I had one continuous path through all **587,664 pixels**.

---

## The Final Mistake Before Solving

Even after finding the correct path, I was still using it incorrectly.

I initially assumed the transformation was something like:

```text
row-major data
    ↓
write along Hilbert/Gilbert path
```

or the reverse:

```text
read along path
    ↓
reshape row-major
```

This was wrong.

The actual operation was much simpler.

The pixels were shifted **along the curve itself**.

That is, if:

```text
curve[i]
```

is the coordinate at position `i` along the continuous path, the permutation behaves like a one-dimensional cyclic rotation:

```text
curve[i] → curve[(i + k) mod N]
```

This perfectly matches both hints.

It is:

- just a pixel permutation
- locality-preserving
- based on following a path instead of rows

---

## Recovering the Offset

Once I had the correct permutation model, the remaining unknown was the cyclic offset:

```text
k
```

The correct value turned out to be:

```text
224468
```

The inverse mapping was:

```python
out[curve[i]] = scrambled[curve[(i + 224468) % N]]
```

After applying that permutation, the image immediately became readable.

The recovered image contained the flag repeated multiple times:

```text
LYKNCTF{0548fcfa-6785-4051-a54d-8006b2f4828b}
```

At that point there was no ambiguity.

---

## Solver Script

Here is my final solver:

```python
#!/usr/bin/env python3

from pathlib import Path
import sys

import numpy as np
from PIL import Image


OFFSET = 224468


def sgn(x: int) -> int:
    return (x > 0) - (x < 0)


def generate2d(
    x: int,
    y: int,
    ax: int,
    ay: int,
    bx: int,
    by: int,
):
    """
    Generate a rectangular Gilbert/Hilbert-style path.
    Every pixel coordinate is visited exactly once.
    """

    w = abs(ax + ay)
    h = abs(bx + by)

    dax = sgn(ax)
    day = sgn(ay)
    dbx = sgn(bx)
    dby = sgn(by)

    # Single row
    if h == 1:
        for _ in range(w):
            yield x, y
            x += dax
            y += day
        return

    # Single column
    if w == 1:
        for _ in range(h):
            yield x, y
            x += dbx
            y += dby
        return

    ax2 = ax // 2
    ay2 = ay // 2
    bx2 = bx // 2
    by2 = by // 2

    w2 = abs(ax2 + ay2)
    h2 = abs(bx2 + by2)

    # Long rectangle
    if 2 * w > 3 * h:
        if (w2 % 2) and (w > 2):
            ax2 += dax
            ay2 += day

        yield from generate2d(
            x,
            y,
            ax2,
            ay2,
            bx,
            by,
        )

        yield from generate2d(
            x + ax2,
            y + ay2,
            ax - ax2,
            ay - ay2,
            bx,
            by,
        )

    else:
        # Standard three-part recursion
        if (h2 % 2) and (h > 2):
            bx2 += dbx
            by2 += dby

        yield from generate2d(
            x,
            y,
            bx2,
            by2,
            ax2,
            ay2,
        )

        yield from generate2d(
            x + bx2,
            y + by2,
            ax,
            ay,
            bx - bx2,
            by - by2,
        )

        yield from generate2d(
            x + (ax - dax) + (bx2 - dbx),
            y + (ay - day) + (by2 - dby),
            -bx2,
            -by2,
            -(ax - ax2),
            -(ay - ay2),
        )


def gilbert2d(width: int, height: int):
    if width >= height:
        return list(
            generate2d(
                0,
                0,
                width,
                0,
                0,
                height,
            )
        )

    return list(
        generate2d(
            0,
            0,
            0,
            height,
            width,
            0,
        )
    )


def solve(input_path: Path, output_path: Path):
    img = np.asarray(
        Image.open(input_path).convert("RGB")
    )

    height, width = img.shape[:2]

    total_pixels = width * height

    print(f"[+] Dimensions: {width}x{height}")
    print(f"[+] Total pixels: {total_pixels}")

    curve = np.asarray(
        gilbert2d(width, height),
        dtype=np.int64,
    )

    if len(curve) != total_pixels:
        raise RuntimeError(
            f"Invalid curve length: "
            f"{len(curve)} != {total_pixels}"
        )

    recovered = np.empty_like(img)

    dst = curve

    src = curve[
        (np.arange(total_pixels) + OFFSET)
        % total_pixels
    ]

    recovered[
        dst[:, 1],
        dst[:, 0],
    ] = img[
        src[:, 1],
        src[:, 0],
    ]

    Image.fromarray(recovered).save(output_path)

    print(f"[+] Offset: {OFFSET}")
    print(f"[+] Saved: {output_path}")


def main():
    if len(sys.argv) not in (2, 3):
        print(
            f"Usage: {sys.argv[0]} "
            f"INPUT.jpg [OUTPUT.png]"
        )
        return 1

    input_path = Path(sys.argv[1])

    output_path = (
        Path(sys.argv[2])
        if len(sys.argv) == 3
        else Path("recovered.png")
    )

    solve(input_path, output_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Usage:

```bash
python3 solve.py chall.jpg recovered.png
```

---

## Flag

```text
LYKNCTF{0548fcfa-6785-4051-a54d-8006b2f4828b}
```

---

## Final Thoughts

Honestly, this challenge became much easier once I stopped treating it as a traditional image steganography problem.

My biggest mistake was assuming that a noisy-looking JPEG must contain something hidden in:

```text
metadata
LSBs
color channels
DCT coefficients
frequency space
```

The first hint completely changed the problem:

> **It's just a pixel permutation.**

And the second hint gave away the mathematical property I should have focused on:

> **Nearby pixels tend to stay nearby. Try following a path instead of rows.**

The final insight was that I should not merely convert between row-major and Hilbert-major order. The permutation was a **cyclic shift along one continuous locality-preserving path**.

Once I modeled the image as:

```text
2D pixels
→ one continuous rectangular Gilbert path
→ cyclic shift
→ inverse shift
```

the challenge fell apart almost immediately.

The title **One Stroke** was also a really nice clue in hindsight. The entire image was effectively being treated as one long continuous stroke through every pixel.

Definitely one of those challenges where the intended solution feels almost embarrassingly simple only after finding the correct abstraction.

</details>
