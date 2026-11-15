//! `Array.prototype.sort` exactly as V8 does it (its TimSort, from third_party/v8/builtins/
//! array-sort.tq, itself after CPython's listsort). With a consistent comparison any stable sort
//! would do; the store's comparison isn't consistent when a field mixes types (as JavaScript's `<`
//! isn't), and then only the same algorithm gives the same order. It also never panics on an
//! inconsistent comparison, which the standard library's sort may.
const MIN_GALLOP_WINS: usize = 7;

struct State<'a, T, F> {
    a: &'a mut [T],
    cmp: F,
    min_gallop: usize,
    runs: Vec<(usize, usize)>,
}

/// Sort `a` with a comparison that answers like a JavaScript compare function (`< 0`, `0`, `> 0`).
pub fn sort<T: Clone, F: FnMut(&T, &T) -> i64>(a: &mut [T], cmp: F) {
    let n = a.len();
    if n < 2 {
        return;
    }
    let mut s = State { a, cmp, min_gallop: MIN_GALLOP_WINS, runs: Vec::new() };
    let min_run = compute_min_run(n);
    let (mut low, mut remaining) = (0, n);
    while remaining != 0 {
        let mut current = s.count_and_make_run(low, low + remaining);
        if current < min_run {
            let forced = remaining.min(min_run);
            s.binary_insertion_sort(low, low + current, low + forced);
            current = forced;
        }
        s.runs.push((low, current));
        s.merge_collapse();
        low += current;
        remaining -= current;
    }
    s.merge_force_collapse();
}

fn compute_min_run(mut n: usize) -> usize {
    let mut r = 0;
    while n >= 64 {
        r |= n & 1;
        n >>= 1;
    }
    n + r
}

impl<T: Clone, F: FnMut(&T, &T) -> i64> State<'_, T, F> {
    fn c(&mut self, x: &T, y: &T) -> i64 {
        (self.cmp)(x, y)
    }

    fn binary_insertion_sort(&mut self, low: usize, start_arg: usize, high: usize) {
        let mut start = if low == start_arg { start_arg + 1 } else { start_arg };
        while start < high {
            let (mut left, mut right) = (low, start);
            let pivot = self.a[start].clone();
            while left < right {
                let mid = left + ((right - left) >> 1);
                let m = self.a[mid].clone();
                if self.c(&pivot, &m) < 0 {
                    right = mid;
                } else {
                    left = mid + 1;
                }
            }
            let mut p = start;
            while p > left {
                self.a[p] = self.a[p - 1].clone();
                p -= 1;
            }
            self.a[left] = pivot;
            start += 1;
        }
    }

    fn count_and_make_run(&mut self, low_arg: usize, high: usize) -> usize {
        let low = low_arg + 1;
        if low == high {
            return 1;
        }
        let mut run = 2;
        let (el, pre) = (self.a[low].clone(), self.a[low - 1].clone());
        let descending = self.c(&el, &pre) < 0;
        let mut previous = el;
        for idx in low + 1..high {
            let current = self.a[idx].clone();
            let order = self.c(&current, &previous);
            if descending {
                if order >= 0 {
                    break;
                }
            } else if order < 0 {
                break;
            }
            previous = current;
            run += 1;
        }
        if descending {
            self.a[low - 1..low - 1 + run].reverse();
        }
        run
    }

    fn len(&self, i: usize) -> usize {
        self.runs[i].1
    }

    fn invariant(&self, n: usize) -> bool {
        n < 2 || self.len(n - 2) > self.len(n - 1) + self.len(n)
    }

    fn merge_collapse(&mut self) {
        while self.runs.len() > 1 {
            let mut n = self.runs.len() - 2;
            if !self.invariant(n + 1) || !self.invariant(n) {
                if self.len(n - 1) < self.len(n + 1) {
                    n -= 1;
                }
                self.merge_at(n);
            } else if self.len(n) <= self.len(n + 1) {
                self.merge_at(n);
            } else {
                break;
            }
        }
    }

    fn merge_force_collapse(&mut self) {
        while self.runs.len() > 1 {
            let mut n = self.runs.len() - 2;
            if n > 0 && self.len(n - 1) < self.len(n + 1) {
                n -= 1;
            }
            self.merge_at(n);
        }
    }

    fn merge_at(&mut self, i: usize) {
        let (mut base_a, mut len_a) = self.runs[i];
        let (base_b, mut len_b) = self.runs[i + 1];
        self.runs[i].1 = len_a + len_b;
        self.runs.remove(i + 1);
        let key = self.a[base_b].clone();
        let k = gallop_right(&mut self.cmp, self.a, &key, base_a, len_a, 0);
        base_a += k;
        len_a -= k;
        if len_a == 0 {
            return;
        }
        let key = self.a[base_a + len_a - 1].clone();
        len_b = gallop_left(&mut self.cmp, self.a, &key, base_b, len_b, len_b - 1);
        if len_b == 0 {
            return;
        }
        if len_a <= len_b {
            self.merge_low(base_a, len_a, base_b, len_b);
        } else {
            self.merge_high(base_a, len_a, base_b, len_b);
        }
    }

    fn merge_low(&mut self, base_a: usize, mut len_a: usize, base_b: usize, mut len_b: usize) {
        let temp: Vec<T> = self.a[base_a..base_a + len_a].to_vec();
        let (mut dest, mut ct, mut cb) = (base_a, 0usize, base_b);
        self.a[dest] = self.a[cb].clone();
        dest += 1;
        cb += 1;
        enum End {
            Succeed,
            CopyB,
        }
        let end = 'outer: {
            len_b -= 1;
            if len_b == 0 {
                break 'outer End::Succeed;
            }
            if len_a == 1 {
                break 'outer End::CopyB;
            }
            let mut min_gallop = self.min_gallop;
            loop {
                let (mut wins_a, mut wins_b) = (0usize, 0usize);
                loop {
                    let (x, y) = (self.a[cb].clone(), temp[ct].clone());
                    if self.c(&x, &y) < 0 {
                        self.a[dest] = x;
                        dest += 1;
                        cb += 1;
                        wins_b += 1;
                        len_b -= 1;
                        wins_a = 0;
                        if len_b == 0 {
                            break 'outer End::Succeed;
                        }
                        if wins_b >= min_gallop {
                            break;
                        }
                    } else {
                        self.a[dest] = y;
                        dest += 1;
                        ct += 1;
                        wins_a += 1;
                        len_a -= 1;
                        wins_b = 0;
                        if len_a == 1 {
                            break 'outer End::CopyB;
                        }
                        if wins_a >= min_gallop {
                            break;
                        }
                    }
                }
                min_gallop += 1;
                let mut first = true;
                while wins_a >= MIN_GALLOP_WINS || wins_b >= MIN_GALLOP_WINS || first {
                    first = false;
                    min_gallop = min_gallop.saturating_sub(1).max(1);
                    self.min_gallop = min_gallop;
                    let key = self.a[cb].clone();
                    wins_a = gallop_right(&mut self.cmp, &temp, &key, ct, len_a, 0);
                    if wins_a > 0 {
                        self.a[dest..dest + wins_a].clone_from_slice(&temp[ct..ct + wins_a]);
                        dest += wins_a;
                        ct += wins_a;
                        len_a -= wins_a;
                        if len_a == 1 {
                            break 'outer End::CopyB;
                        }
                        if len_a == 0 {
                            break 'outer End::Succeed;
                        }
                    }
                    self.a[dest] = self.a[cb].clone();
                    dest += 1;
                    cb += 1;
                    len_b -= 1;
                    if len_b == 0 {
                        break 'outer End::Succeed;
                    }
                    let key = temp[ct].clone();
                    wins_b = gallop_left(&mut self.cmp, self.a, &key, cb, len_b, 0);
                    if wins_b > 0 {
                        copy_within(self.a, cb, dest, wins_b);
                        dest += wins_b;
                        cb += wins_b;
                        len_b -= wins_b;
                        if len_b == 0 {
                            break 'outer End::Succeed;
                        }
                    }
                    self.a[dest] = temp[ct].clone();
                    dest += 1;
                    ct += 1;
                    len_a -= 1;
                    if len_a == 1 {
                        break 'outer End::CopyB;
                    }
                }
                min_gallop += 1;
                self.min_gallop = min_gallop;
            }
        };
        match end {
            End::Succeed => {
                if len_a > 0 {
                    self.a[dest..dest + len_a].clone_from_slice(&temp[ct..ct + len_a]);
                }
            }
            End::CopyB => {
                copy_within(self.a, cb, dest, len_b);
                self.a[dest + len_b] = temp[ct].clone();
            }
        }
    }

    fn merge_high(&mut self, base_a: usize, mut len_a: usize, base_b: usize, mut len_b: usize) {
        let temp: Vec<T> = self.a[base_b..base_b + len_b].to_vec();
        // Positions can go one below zero at the very end, as in V8: keep them signed.
        let (mut dest, mut ct, mut ca) = ((base_b + len_b - 1) as isize, len_b as isize - 1, (base_a + len_a - 1) as isize);
        let at = |i: isize| i as usize;
        self.a[at(dest)] = self.a[at(ca)].clone();
        dest -= 1;
        ca -= 1;
        enum End {
            Succeed,
            CopyA,
        }
        let end = 'outer: {
            len_a -= 1;
            if len_a == 0 {
                break 'outer End::Succeed;
            }
            if len_b == 1 {
                break 'outer End::CopyA;
            }
            let mut min_gallop = self.min_gallop;
            loop {
                let (mut wins_a, mut wins_b) = (0usize, 0usize);
                loop {
                    let (x, y) = (temp[at(ct)].clone(), self.a[at(ca)].clone());
                    if self.c(&x, &y) < 0 {
                        self.a[at(dest)] = y;
                        dest -= 1;
                        ca -= 1;
                        wins_a += 1;
                        len_a -= 1;
                        wins_b = 0;
                        if len_a == 0 {
                            break 'outer End::Succeed;
                        }
                        if wins_a >= min_gallop {
                            break;
                        }
                    } else {
                        self.a[at(dest)] = x;
                        dest -= 1;
                        ct -= 1;
                        wins_b += 1;
                        len_b -= 1;
                        wins_a = 0;
                        if len_b == 1 {
                            break 'outer End::CopyA;
                        }
                        if wins_b >= min_gallop {
                            break;
                        }
                    }
                }
                min_gallop += 1;
                let mut first = true;
                while wins_a >= MIN_GALLOP_WINS || wins_b >= MIN_GALLOP_WINS || first {
                    first = false;
                    min_gallop = min_gallop.saturating_sub(1).max(1);
                    self.min_gallop = min_gallop;
                    let key = temp[at(ct)].clone();
                    let k = gallop_right(&mut self.cmp, self.a, &key, base_a, len_a, len_a - 1);
                    wins_a = len_a - k;
                    if wins_a > 0 {
                        dest -= wins_a as isize;
                        ca -= wins_a as isize;
                        copy_within(self.a, at(ca + 1), at(dest + 1), wins_a);
                        len_a -= wins_a;
                        if len_a == 0 {
                            break 'outer End::Succeed;
                        }
                    }
                    self.a[at(dest)] = temp[at(ct)].clone();
                    dest -= 1;
                    ct -= 1;
                    len_b -= 1;
                    if len_b == 1 {
                        break 'outer End::CopyA;
                    }
                    let key = self.a[at(ca)].clone();
                    let k = gallop_left(&mut self.cmp, &temp, &key, 0, len_b, len_b - 1);
                    wins_b = len_b - k;
                    if wins_b > 0 {
                        dest -= wins_b as isize;
                        ct -= wins_b as isize;
                        self.a[at(dest + 1)..at(dest + 1) + wins_b].clone_from_slice(&temp[at(ct + 1)..at(ct + 1) + wins_b]);
                        len_b -= wins_b;
                        if len_b == 1 {
                            break 'outer End::CopyA;
                        }
                        if len_b == 0 {
                            break 'outer End::Succeed;
                        }
                    }
                    self.a[at(dest)] = self.a[at(ca)].clone();
                    dest -= 1;
                    ca -= 1;
                    len_a -= 1;
                    if len_a == 0 {
                        break 'outer End::Succeed;
                    }
                }
                min_gallop += 1;
                self.min_gallop = min_gallop;
            }
        };
        match end {
            End::Succeed => {
                if len_b > 0 {
                    let to = at(dest - (len_b as isize - 1));
                    self.a[to..to + len_b].clone_from_slice(&temp[..len_b]);
                }
            }
            End::CopyA => {
                dest -= len_a as isize;
                ca -= len_a as isize;
                copy_within(self.a, at(ca + 1), at(dest + 1), len_a);
                self.a[at(dest)] = temp[at(ct)].clone();
            }
        }
    }
}

/// `memmove` within one slice.
fn copy_within<T: Clone>(a: &mut [T], from: usize, to: usize, n: usize) {
    if n == 0 || from == to {
        return;
    }
    if from < to {
        for i in (0..n).rev() {
            a[to + i] = a[from + i].clone();
        }
    } else {
        for i in 0..n {
            a[to + i] = a[from + i].clone();
        }
    }
}

/// The position in `arr[base..base+len]` where `key` goes, leftmost among equals.
fn gallop_left<T: Clone, F: FnMut(&T, &T) -> i64>(cmp: &mut F, arr: &[T], key: &T, base: usize, len: usize, hint: usize) -> usize {
    let (mut last, mut offset): (isize, isize) = (0, 1);
    let hint_i = hint as isize;
    if cmp(&arr[base + hint], key) < 0 {
        let max = (len - hint) as isize;
        while offset < max {
            if cmp(&arr[base + hint + offset as usize], key) >= 0 {
                break;
            }
            last = offset;
            offset = (offset << 1) + 1;
        }
        offset = offset.min(max);
        last += hint_i;
        offset += hint_i;
    } else {
        let max = hint_i + 1;
        while offset < max {
            if cmp(&arr[base + (hint_i - offset) as usize], key) < 0 {
                break;
            }
            last = offset;
            offset = (offset << 1) + 1;
        }
        offset = offset.min(max);
        let tmp = last;
        last = hint_i - offset;
        offset = hint_i - tmp;
    }
    last += 1;
    while last < offset {
        let m = last + ((offset - last) >> 1);
        if cmp(&arr[base + m as usize], key) < 0 {
            last = m + 1;
        } else {
            offset = m;
        }
    }
    offset as usize
}

/// The position in `arr[base..base+len]` where `key` goes, rightmost among equals.
fn gallop_right<T: Clone, F: FnMut(&T, &T) -> i64>(cmp: &mut F, arr: &[T], key: &T, base: usize, len: usize, hint: usize) -> usize {
    let (mut last, mut offset): (isize, isize) = (0, 1);
    let hint_i = hint as isize;
    if cmp(key, &arr[base + hint]) < 0 {
        let max = hint_i + 1;
        while offset < max {
            if cmp(key, &arr[base + (hint_i - offset) as usize]) >= 0 {
                break;
            }
            last = offset;
            offset = (offset << 1) + 1;
        }
        offset = offset.min(max);
        let tmp = last;
        last = hint_i - offset;
        offset = hint_i - tmp;
    } else {
        let max = (len - hint) as isize;
        while offset < max {
            if cmp(key, &arr[base + hint + offset as usize]) < 0 {
                break;
            }
            last = offset;
            offset = (offset << 1) + 1;
        }
        offset = offset.min(max);
        last += hint_i;
        offset += hint_i;
    }
    last += 1;
    while last < offset {
        let m = last + ((offset - last) >> 1);
        if cmp(key, &arr[base + m as usize]) < 0 {
            offset = m;
        } else {
            last = m + 1;
        }
    }
    offset as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_and_is_stable() {
        let mut r = 12345u64;
        for n in [0, 1, 2, 5, 31, 32, 33, 64, 65, 100, 1000, 5000] {
            let mut v: Vec<(u64, usize)> = (0..n)
                .map(|i| {
                    r = r.wrapping_mul(6364136223846793005).wrapping_add(1);
                    ((r >> 33) % 50, i)
                })
                .collect();
            let mut want = v.clone();
            want.sort_by_key(|x| x.0);
            sort(&mut v, |a, b| a.0 as i64 - b.0 as i64);
            assert_eq!(v, want, "n = {n}");
        }
    }

    #[test]
    fn an_inconsistent_comparison_never_panics() {
        let mut v: Vec<u32> = (0..3000).map(|i| (i * 7919) % 1013).collect();
        let mut flip = 0u64;
        sort(&mut v, |a, b| {
            flip = flip.wrapping_mul(31).wrapping_add(u64::from(*a ^ *b));
            if flip.is_multiple_of(3) { -1 } else { 1 }
        });
        assert_eq!(v.len(), 3000);
    }
}
