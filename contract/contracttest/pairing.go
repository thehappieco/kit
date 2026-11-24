package contracttest

// The relink's pairing route (SPEC section 11.19; the platform's decision
// 0057): while an item.relink runs, the app sends each QR WhatsApp gives
// it, PUT /contract/v1/commands/{id}/pairing, and the fake holds the
// latest, as the platform holds it in memory for the actor's page. The
// call checks, in the platform's order:
//  1. the command: an item.relink of the app's that a command feed answer
//     carried, with no final result kept, else not_found, signed (the app
//     sends no more QRs for it); an {id} that is no UUID is no call, an
//     unsigned not_found, at the transport's step 4;
//  2. the body, read strictly (contract.DecodeStrict) and valid at the
//     fake's clock (contract.PairingQR.ValidateAt), else invalid_request,
//     signed;
//  3. a seq at or below the highest the fake kept for the command, or a
//     PUT more than contract.PairingHold after its first QR, answered
//     accepted false, holding nothing; else accepted true, the QR held.
//
// The QR held goes at the earliest of its expires_at, the command's final
// result and contract.PairingHold after the first QR; a final result also
// drops the seq and the first QR's time, and Restore and NewGeneration drop
// everything, so the next PUT counts as the first. The fake never logs a
// QR, and Pairing returns it only while it is held.

import (
	"net/http"
	"time"

	"github.com/thehappieco/kit/contract"
)

// pairing is what the fake keeps of a running relink's QRs.
type pairing struct {
	// qr is the QR held, nil once it went.
	qr *contract.PairingQR
	// seq is the highest seq kept, and first the time of the first QR.
	seq   int64
	first time.Time
}

// putPairing answers PUT /contract/v1/commands/{id}/pairing, the steps
// of the file's comment.
func (p *Platform) putPairing(rq *request) answer {
	p.mu.Lock()
	defer p.mu.Unlock()
	app := rq.app
	now := p.now()
	p.settleCommandsLocked(app, now)
	c := app.cmdByID[rq.arg]
	if c == nil || c.c.Kind != contract.OpItemRelink || !c.carried || c.final != nil {
		return refusal(contract.CodeNotFound, "no relink of the app's runs under this id")
	}
	var q contract.PairingQR
	if err := decodeContract(rq.body, &q); err != nil || q.ValidateAt(now) != nil {
		return refusal(contract.CodeInvalid, "the pairing is not valid")
	}
	held := app.pairings[rq.arg]
	switch {
	case held == nil:
		held = &pairing{first: atMicroseconds(now)}
		app.pairings[rq.arg] = held
	case q.Seq <= held.seq, now.After(held.first.Add(contract.PairingHold)):
		return answer{status: http.StatusOK, body: contract.PairingAnswer{Accepted: false}}
	}
	held.qr, held.seq = &q, q.Seq
	return answer{status: http.StatusOK, body: contract.PairingAnswer{Accepted: true}}
}

// prunePairings drops, at now, the pairings of a command that is gone or
// has a final result, and the QR held past its expires_at or more than
// contract.PairingHold after the first QR.
func (a *settingsApp) prunePairings(now time.Time) {
	for id, held := range a.pairings {
		if c := a.cmdByID[id]; c == nil || c.final != nil {
			delete(a.pairings, id)
			continue
		}
		if held.qr != nil && (!now.Before(held.qr.ExpiresAt) || now.After(held.first.Add(contract.PairingHold))) {
			held.qr = nil
		}
	}
}

// Pairing is the QR the fake holds for app's item.relink id: the latest
// the app sent and the fake accepted, while it holds it (before its
// expires_at, the command's final result and contract.PairingHold after
// the first QR, by the fake's clock); false otherwise.
func (p *Platform) Pairing(app, id string) (contract.PairingQR, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.PairingQR{}, false
	}
	p.settleCommandsLocked(st, p.now())
	held := st.pairings[id]
	if held == nil || held.qr == nil {
		return contract.PairingQR{}, false
	}
	return *held.qr, true
}
