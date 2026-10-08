#!/bin/sh
# identifiers-check.sh [<rev>...]: fails if the kit names an identifier of a
# real AWS account in a tracked file of any commit reachable from the
# revisions given (HEAD by default; git rev-list syntax, so --all checks
# every branch), in a path of one, or in one of their commit messages. The
# repository is public and its history is published with every branch, so a
# value committed and then removed counts as published.
#
# Two checks, and this file names no real value in either:
#
#  1. Classes of identifier, whatever their value, of which only AWS's
#     documentation placeholders and the kit's own test values are allowed:
#     an account id in an ARN or in an account-id field, an EC2 or VPC
#     resource id, a KMS key id, a KMS alias, an S3 bucket, an IAM role or
#     instance profile in an ARN, and an IAM Identity Center portal.
#  2. The owner's private list: one string per line, matched as a fixed
#     string without regard to case, from $KIT_IDENTIFIERS (in CI, the
#     repository secret of that name) or else from identifiers.local.txt at
#     the repository's root (git-ignored, *.local.*). The list never goes
#     into the repository: a public rule would have to spell the values it
#     forbids. With CI=true and no list, the check fails.
#
# A match is reported by commit, path, line and the check that matched,
# never by what matched. Run by make identifiers-check, which CI runs.
set -eu

[ $# -gt 0 ] || set -- HEAD
cd "$(git rev-parse --show-toplevel)"
revs=$(git rev-list "$@")
[ -n "$revs" ] || { echo "identifiers-check: no commit in $*"; exit 1; }
count=$(printf '%s\n' "$revs" | wc -l | tr -d ' ')

list=$(mktemp)
found=$(mktemp)
hits=$(mktemp)
trap 'rm -f "$list" "$found" "$hits"' EXIT

# grep_revs <git grep options>...: git grep over every commit, into $hits.
# Exit status 1 is no match; anything else but 0 is an error, which fails
# the check rather than pass it unread.
grep_revs() {
	rc=0
	# shellcheck disable=SC2086 # one commit per word
	git grep "$@" $revs > "$hits" || rc=$?
	[ "$rc" -le 1 ] || { echo "identifiers-check: git grep failed ($rc)"; exit 1; }
}

# One value per line; carriage returns, surrounding blanks and blank lines
# go, so a list pasted into the secret's form matches as written.
clean() { tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | grep -v '^$' || true; }
if [ -n "${KIT_IDENTIFIERS:-}" ]; then
	printf '%s\n' "$KIT_IDENTIFIERS" | clean > "$list"
elif [ -f identifiers.local.txt ]; then
	clean < identifiers.local.txt > "$list"
fi
if [ ! -s "$list" ]; then
	if [ "${CI:-}" = true ]; then
		echo "identifiers-check: no private list: the repository secret KIT_IDENTIFIERS is empty or not passed to this job"
		exit 1
	fi
	echo "identifiers-check: no private list (KIT_IDENTIFIERS or identifiers.local.txt), so the classes only"
fi

# The only values a class may hold, matched without regard to case: AWS's
# documentation placeholders, and the kit's own test values (the awskms
# tests' malformed 11-digit account and their key id, which the platform's
# tests have used since before the account had a key).
accounts='^(111122223333|11112222333|123456789012|444455556666|777788889999|000000000000)$'
resources='^(i-1234567890abcdef0|i-0123456789abcdef0)$'
keyids='^(1234abcd-12ab-34cd-56ef-1234567890ab|0b9e3c1d-5a2f-4e8b-9c7d-1f2a3b4c5d6e|mrk-1234abcd12ab34cd56ef1234567890ab)$'
aliases='^alias/(example-alias|aws/[a-z0-9_-]+)$'
buckets='^(amzn-s3-demo-bucket[a-z0-9.-]*|example-bucket|bucket)$'
roles='^example-[a-z0-9+=,.@_-]*$'

# class <name> <pattern> <value> <allowed>: every match of the extended
# regular expression <pattern> in a text file of a commit, reduced to the
# first match of <value> in it, must match <allowed>.
class() {
	grep_revs -I -n -o -E -e "$2"
	while IFS= read -r hit; do
		rev=${hit%%:*}
		rest=${hit#*:}
		path=${rest%%:*}
		rest=${rest#*:}
		line=${rest%%:*}
		match=${rest#*:}
		value=$(printf '%s\n' "$match" | grep -o -E -e "$3" | head -n 1) || value=
		if ! printf '%s\n' "$value" | grep -q -i -E -e "$4"; then
			echo "$(echo "$rev" | cut -c1-12) $path:$line: $1" >> "$found"
		fi
	done < "$hits"
}
hex='[0-9A-Fa-f]'
uuid="${hex}{8}-${hex}{4}-${hex}{4}-${hex}{4}-${hex}{12}"
field='["'\'']?[[:space:]]*[:=][[:space:]]*["'\'']?'
class 'an AWS account id in an ARN' 'arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]+:' '[0-9]+:$' "$(printf '%s' "$accounts" | sed 's/)\$$/):$/')"
class 'an AWS account id in a field' "([Aa]ccount_?[Ii][Dd]|AWS_ACCOUNT_ID|AWSAccountId)${field}[0-9]{10,13}" '[0-9]{10,13}$' "$accounts"
class 'an EC2 or VPC resource id' "(^|[^A-Za-z0-9_-])(i|sg|subnet|vpc|vpce|vol|snap|ami|eni|igw|rtb|nat|eipalloc|lt|tgw)-(${hex}{17}|${hex}{8})([^A-Za-z0-9_-]|\$)" '[a-z]+-[0-9A-Fa-f]+' "$resources"
class 'a KMS key id' "(:key/|KeyId${field})(mrk-${hex}{32}|$uuid)" "(mrk-${hex}{32}|$uuid)\$" "$keyids"
class 'a KMS alias' 'alias/[A-Za-z0-9/_-]+' 'alias/[A-Za-z0-9/_-]+' "$aliases"
class 'an S3 bucket' '(s3://|arn:aws[a-z-]*:s3:::)[A-Za-z0-9.-]+' '[A-Za-z0-9.-]+$' "$buckets"
class 'an IAM role or instance profile in an ARN' ':(role|assumed-role|instance-profile)/[A-Za-z0-9+=,.@_-]+' '[A-Za-z0-9+=,.@_-]+$' "$roles"
class 'an IAM Identity Center portal' '[A-Za-z0-9-]+\.awsapps\.com' '.*' '^$'

if [ -s "$list" ]; then
	grep_revs --text -n -i -F -f "$list"
	awk -F: '{ print substr($1, 1, 12) " " $2 ":" $3 ": an identifier of the private list" }' "$hits" >> "$found"
	for rev in $revs; do
		short=$(echo "$rev" | cut -c1-12)
		git log -1 --format=%B "$rev" | grep -n -i -F -f "$list" |
			awk -F: -v r="$short" '{ print r " commit message, line " $1 ": an identifier of the private list" }' >> "$found" || true
		if git ls-tree -r --name-only "$rev" | grep -q -i -F -f "$list"; then
			echo "$short a path: an identifier of the private list" >> "$found"
		fi
	done
fi

if [ -s "$found" ]; then
	sort -u "$found"
	echo "identifiers-check: $(sort -u "$found" | wc -l | tr -d ' ') matches in $count commits"
	exit 1
fi
echo "identifiers-check: $count commits, no identifier of an AWS account"
