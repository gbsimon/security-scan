"""Pull evaluation artefacts. Nothing here is dynamic."""
import argparse


def check(s):
    # A message that happens to mention the function by name.
    if not s.isidentifier():
        raise SystemExit(f"refusing to eval(s) untrusted input: {s!r}")
    return s


def run(model, batch):
    model.eval()          # torch: switch to inference mode, not a call to eval
    return [check(x) for x in batch]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", nargs="*", default=[])
    print(run(object(), ap.parse_args().batch))
