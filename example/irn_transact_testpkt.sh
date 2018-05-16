#!/usr/bin/env sh

CURL=curl
ATMI_IRN_ACT='http://device.atonomi.net/activate'

PAYLOAD_TX=testonly_actreq.packet.bin
PAYLOAD_RX=testonly_actresp.packet.bin

# Headers: Send content type.
# Headers: Don't send unnecessary user-agent (for clarity).
HDR_CTYPE='Content-Type: application/octet-stream'
HDR_AGENT='User-Agent: '

STDOUT_HDRS_ASCIIHEX="-s --trace-ascii -"
STDOUT_HDRS_ASCII="-s --verbose"
STDOUT_SILENT="-s"
STDOUT_PRINT="${STDOUT_HDRS_ASCIIHEX}"

${CURL} --version >/dev/null 2>&1

if test "$?" -ne 0 ; then
	echo "Error: curl is required, but does not seem to be available?"
	exit 1
fi

exec ${CURL} --http1.1 \
	-X 'PUT' \
	--data-binary "@${PAYLOAD_TX}" \
	-H "${HDR_CTYPE}" \
	-H "${HDR_AGENT}" \
	-o "${PAYLOAD_RX}" \
	${STDOUT_PRINT} \
	"${ATMI_IRN_ACT}"

