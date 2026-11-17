
import time

with open('list.txt', 'r') as f:
    old = [i.rstrip('\n') for i in f.readlines()]
    print(f"Imported old list ({len(old)})")
    print(f"Cleaned old list ({len(old)})")

with open('merged_blocklist.txt', 'r') as f:
    new = [i.rstrip('\n') for i in f.readlines()]
    print(f"Imported new list ({len(new)})")
    print(f"Cleaned new list ({len(new)}), comparing...")

keep = []
old_set = set(old)
total = len(new)
start = time.time()

for index, item in enumerate(new, 1):
    if item not in old_set:
        keep.append(item)

    if index % 100000 == 0 or index == total:
        elapsed = time.time() - start
        speed = index / elapsed if elapsed > 0 else 0
        remaining = (total - index) / speed if speed > 0 else 0

        print(
            f"Progress: {index}/{total} "
            f"({index / total * 100:.2f}%) | "
            f"Speed: {speed:.0f}/s | "
            f"ETA: {remaining:.1f}s"
        )

print("Comparing done. Writing")

with open('list_new.txt', 'w') as f:
    for i in keep:
        f.write(i + '\n')

print(f"All done. Found {len(keep)} new entries.")
