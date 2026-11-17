// The instance buffer: one fixed 56-byte record per tile, the SAME
// layout for the Canvas2D renderer and a GPU backend (which uploads it
// as an instanced vertex buffer). The engine writes only records whose
// state changed and reports them as dirty ranges; per-frame motion is
// computed by the renderer from {from, to, t0, dur}.
//
// Record layout (little-endian, 14 × 4-byte words, stride 56 B):
//   word  0..3   from rect   x, y, w, h        f32   (16 B)
//   word  4..7   to rect     x, y, w, h        f32   (16 B)
//   word  8      from colour RGBA8             u32   ( 4 B)
//   word  9      to colour   RGBA8             u32   ( 4 B)
//   word 10      t0  (ms, engine clock)        f32   ( 4 B)
//   word 11      dur (ms; ≤ 0 = settled)       f32   ( 4 B)
//   word 12      flags (FLAG_*, kind << 8)     u32   ( 4 B)
//   word 13      pad (0)                       u32   ( 4 B)
//
// A free slot has both colours fully transparent; renderers skip it.

export const RECORD_BYTES = 56;
export const RECORD_WORDS = RECORD_BYTES / 4;

export const W_FROM_X = 0;
export const W_FROM_Y = 1;
export const W_FROM_W = 2;
export const W_FROM_H = 3;
export const W_TO_X = 4;
export const W_TO_Y = 5;
export const W_TO_W = 6;
export const W_TO_H = 7;
export const W_FROM_RGBA = 8;
export const W_TO_RGBA = 9;
export const W_T0 = 10;
export const W_DUR = 11;
export const W_FLAGS = 12;
export const W_PAD = 13;

/** Half-open range of record indices [start, end). */
export interface DirtyRange {
  start: number;
  end: number;
}

export interface RecordState {
  fromX: number; fromY: number; fromW: number; fromH: number;
  toX: number; toY: number; toW: number; toH: number;
  fromRgba: number; toRgba: number;
  t0: number; dur: number;
  flags: number;
}

const littleEndian = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1;

export class InstanceBuffer {
  /** Number of slots in use, counting freed holes below the high-water
   *  mark. Renderers draw records [0, count). */
  count = 0;
  /** Bumped whenever the backing ArrayBuffer is replaced (growth); a GPU
   *  renderer must then re-allocate and re-upload everything. */
  generation = 0;
  private buf: ArrayBuffer;
  private _f32: Float32Array;
  private _u32: Uint32Array;
  /** Released slots below `count`, reused before the buffer grows. */
  private free = new Set<number>();
  private dirtyLo = Infinity;
  private dirtyHi = -Infinity;

  constructor(capacity = 64) {
    if (!littleEndian) throw new Error('InstanceBuffer: big-endian hosts are not supported');
    this.buf = new ArrayBuffer(Math.max(1, capacity) * RECORD_BYTES);
    this._f32 = new Float32Array(this.buf);
    this._u32 = new Uint32Array(this.buf);
  }

  get capacity(): number { return this.buf.byteLength / RECORD_BYTES; }
  get f32(): Float32Array { return this._f32; }
  get u32(): Uint32Array { return this._u32; }
  get bytes(): ArrayBuffer { return this.buf; }

  /** Claim a slot (a freed one first). */
  alloc(): number {
    for (const slot of this.free) {
      this.free.delete(slot);
      return slot;
    }
    if (this.count === this.capacity) this.grow(this.capacity * 2);
    return this.count++;
  }

  /** Release a slot: it becomes transparent and is reused later. */
  release(slot: number): void {
    const o = slot * RECORD_WORDS;
    this._u32.fill(0, o, o + RECORD_WORDS);
    this.markDirty(slot);
    this.free.add(slot);
    // Trim trailing holes so renderers stop early.
    while (this.count > 0 && this.free.has(this.count - 1)) {
      this.free.delete(this.count - 1);
      this.count--;
    }
  }

  /** Number of released slots awaiting reuse (for tests). */
  get holes(): number { return this.free.size; }

  write(slot: number, r: RecordState): void {
    const o = slot * RECORD_WORDS;
    const f = this._f32, u = this._u32;
    f[o + W_FROM_X] = r.fromX; f[o + W_FROM_Y] = r.fromY; f[o + W_FROM_W] = r.fromW; f[o + W_FROM_H] = r.fromH;
    f[o + W_TO_X] = r.toX; f[o + W_TO_Y] = r.toY; f[o + W_TO_W] = r.toW; f[o + W_TO_H] = r.toH;
    u[o + W_FROM_RGBA] = r.fromRgba >>> 0;
    u[o + W_TO_RGBA] = r.toRgba >>> 0;
    f[o + W_T0] = r.t0;
    f[o + W_DUR] = r.dur;
    u[o + W_FLAGS] = r.flags >>> 0;
    u[o + W_PAD] = 0;
    this.markDirty(slot);
  }

  read(slot: number): RecordState {
    const o = slot * RECORD_WORDS;
    const f = this._f32, u = this._u32;
    return {
      fromX: f[o + W_FROM_X]!, fromY: f[o + W_FROM_Y]!, fromW: f[o + W_FROM_W]!, fromH: f[o + W_FROM_H]!,
      toX: f[o + W_TO_X]!, toY: f[o + W_TO_Y]!, toW: f[o + W_TO_W]!, toH: f[o + W_TO_H]!,
      fromRgba: u[o + W_FROM_RGBA]!, toRgba: u[o + W_TO_RGBA]!,
      t0: f[o + W_T0]!, dur: f[o + W_DUR]!,
      flags: u[o + W_FLAGS]!,
    };
  }

  /** Dirty ranges since the last call, then cleared. */
  takeDirty(): DirtyRange[] {
    if (this.dirtyHi < this.dirtyLo) return [];
    const r: DirtyRange = { start: this.dirtyLo, end: this.dirtyHi + 1 };
    this.dirtyLo = Infinity;
    this.dirtyHi = -Infinity;
    return [r];
  }

  /** Mark every record dirty (e.g. a fresh renderer after a swap). */
  markAllDirty(): void {
    if (this.count === 0) return;
    this.dirtyLo = 0;
    this.dirtyHi = this.count - 1;
  }

  private markDirty(slot: number): void {
    if (slot < this.dirtyLo) this.dirtyLo = slot;
    if (slot > this.dirtyHi) this.dirtyHi = slot;
  }

  private grow(capacity: number): void {
    const next = new ArrayBuffer(capacity * RECORD_BYTES);
    new Uint8Array(next).set(new Uint8Array(this.buf));
    this.buf = next;
    this._f32 = new Float32Array(next);
    this._u32 = new Uint32Array(next);
    this.generation++;
  }
}
