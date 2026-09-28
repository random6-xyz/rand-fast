#!/bin/sh
# Reject CJK characters in everything git tracks.
#
# Repository content must stay English-only: source, docs, comments, commit
# messages, and branch names. This script scans the working tree and the
# commit range of the current branch against a base ref, so a violation is
# caught before it is pushed.
#
# Ranges covered:
#   1. files tracked by git in the working tree
#   2. commit subjects and bodies introduced by this branch
#   3. the branch name itself
#
# Usage: tools/check-no-cjk.sh [base-ref]   (default base ref: main)
# Exit status: 0 when clean, 1 when a CJK character is found, 2 on setup
# failure.
set -u

BASE=${1:-main}

# CJK Unified Ideographs, Extension A, compatibility ideographs, Hiragana,
# Katakana, halfwidth Katakana, Hangul syllables and jamo, CJK punctuation,
# and the fullwidth forms block.
PAT='[一-鿿㐀-䶿豈-﫿぀-ゟ゠-ヿ㄰-㆏㆐-ㆿ가-힯ᄀ-ᇿㄱ-ㆎㅀ-㆏ㇰ-ㇿ㈀-㋿㌀-㍿！-｠]'

# grep -P is GNU grep; fall back to a UTF-8 byte-class pattern otherwise.
if printf '한' | grep -qP "$PAT" 2>/dev/null; then
    GREP_MODE=-P
else
    GREP_MODE=-E
fi

fail() {
    echo "check-no-cjk: $1" >&2
    exit 2
}

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not inside a git repository"

violations=0
report() {
    violations=$((violations + 1))
    echo "check-no-cjk: FAILED - CJK character found in $1" >&2
    shift
    [ "$#" -gt 0 ] && printf '%s\n' "$@" >&2
    return 0
}

# Binary and archive payloads are skipped: they carry no reviewable text.
skip_file() {
    case "$1" in
    *.png|*.jpg|*.jpeg|*.gif|*.ico|*.svg|*.webp|*.pdf|*.zip|*.gz|*.xz|*.bz2|*.woff|*.woff2) return 0 ;;
    esac
    return 1
}

echo "check-no-cjk: scanning tracked files (grep $GREP_MODE)"
for path in $(git ls-files); do
    skip_file "$path" && continue
    [ -f "$path" ] || continue
    if grep -n "$GREP_MODE" "$PAT" -- "$path" >/dev/null 2>&1; then
        report "file $path" "$(grep -n "$GREP_MODE" "$PAT" -- "$path" | head -20)"
    fi
done

echo "check-no-cjk: scanning commit messages $BASE..HEAD"
if git rev-parse --verify --quiet "$BASE" >/dev/null 2>&1; then
    range="$BASE..HEAD"
    if git rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
        hits=$(git log --format='%h %s' "$range" | grep "$GREP_MODE" "$PAT" || true)
        if [ -n "$hits" ]; then
            report "commit messages in $range" "$hits"
        fi
    else
        echo "check-no-cjk: HEAD has no commits yet, skipping commit message scan"
    fi
else
    echo "check-no-cjk: base ref $BASE not found, skipping commit message scan"
fi

branch=$(git rev-parse --abbrev-ref HEAD)
if echo "$branch" | grep -q "$GREP_MODE" "$PAT"; then
    report "branch name" "$branch"
fi

if [ "$violations" -ne 0 ]; then
    echo "check-no-cjk: $violations violation group(s) found" >&2
    exit 1
fi

echo "check-no-cjk: OK (working tree, commit messages, branch name)"
