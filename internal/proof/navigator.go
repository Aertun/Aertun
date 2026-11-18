// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// A coverage proof as an ATT&CK Navigator layer.
//
// The Navigator (github.com/mitre-attack/attack-navigator) is where people
// already look at coverage, and it reads layer files (layer format 4.5).
// A layer drawn from a coverage proof colours each technique by its verdict
// and says the verdict in words in its comment, so nothing in it is told by
// colour alone. It carries no score: the Navigator turns scores into a
// gradient and an aggregate, and either would read as the percentage this
// proof refuses to give.
//
// The layer is not signed and needs no trust: it names the proof it was drawn
// from by digest, and every number in it is the proof's. Only ATT&CK
// Enterprise ids go in it; ATLAS and OWASP ids have no place on that matrix
// and are left out and counted.

// The layer format and the Navigator version it is written for.
const (
	NavigatorLayerFormat = "4.5"
	NavigatorVersion     = "5.2.0"
	NavigatorDomain      = "enterprise-attack"
)

// The colours a layer marks each verdict with: Okabe and Ito's palette,
// distinguishable with the common colour-vision deficiencies and by
// lightness alone.
const (
	colourProven       = "#56b4e9"
	colourInconclusive = "#f0e442"
	colourRefuted      = "#d55e00"
	colourUnclaimed    = "#bbbbbb"
)

var attackID = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// NavigatorLayer is a layer file, with the fields a coverage layer sets.
type NavigatorLayer struct {
	Name                          string               `json:"name"`
	Versions                      NavigatorVersions    `json:"versions"`
	Domain                        string               `json:"domain"`
	Description                   string               `json:"description"`
	Sorting                       int                  `json:"sorting"`
	Layout                        NavigatorLayout      `json:"layout"`
	HideDisabled                  bool                 `json:"hideDisabled"`
	Techniques                    []NavigatorTechnique `json:"techniques"`
	LegendItems                   []NavigatorLegend    `json:"legendItems"`
	Metadata                      []NavigatorMetadata  `json:"metadata"`
	ShowTacticRowBackground       bool                 `json:"showTacticRowBackground"`
	SelectTechniquesAcrossTactics bool                 `json:"selectTechniquesAcrossTactics"`
	SelectSubtechniquesWithParent bool                 `json:"selectSubtechniquesWithParent"`
}

// NavigatorVersions is the versions a layer was written for.
type NavigatorVersions struct {
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

// NavigatorLayout is how the matrix is drawn.
type NavigatorLayout struct {
	Layout                string `json:"layout"`
	ShowID                bool   `json:"showID"`
	ShowName              bool   `json:"showName"`
	ShowAggregateScores   bool   `json:"showAggregateScores"`
	ExpandedSubtechniques string `json:"expandedSubtechniques"`
}

// NavigatorTechnique is one technique's annotation.
type NavigatorTechnique struct {
	TechniqueID       string              `json:"techniqueID"`
	Color             string              `json:"color"`
	Comment           string              `json:"comment"`
	Enabled           bool                `json:"enabled"`
	Metadata          []NavigatorMetadata `json:"metadata"`
	ShowSubtechniques bool                `json:"showSubtechniques"`
}

// NavigatorLegend is one entry of the legend.
type NavigatorLegend struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

// NavigatorMetadata is a name and a value shown with a technique or layer.
type NavigatorMetadata struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CoverageLayer draws a coverage proof as a Navigator layer. digest is the
// proof's statement digest, as the store names it, so the layer says which
// proof it shows. It returns the layer and how many techniques were left out
// for not being ATT&CK Enterprise ids.
func CoverageLayer(st *Statement, digest string) ([]byte, int, error) {
	if err := st.Validate(); err != nil {
		return nil, 0, fmt.Errorf("the proof does not hold together: %w", err)
	}
	ev := st.Predicate.Coverage
	if ev == nil {
		return nil, 0, fmt.Errorf("a layer is drawn from a coverage proof, and this is a %s proof", st.PredicateType)
	}
	if !hex64.MatchString(digest) {
		return nil, 0, fmt.Errorf("a proof is named by the sha256 of its statement")
	}
	layer := NavigatorLayer{
		Name:     "Detection coverage, as proven",
		Versions: NavigatorVersions{Navigator: NavigatorVersion, Layer: NavigatorLayerFormat},
		Domain:   NavigatorDomain,
		Description: fmt.Sprintf("Each technique's verdict from coverage proof %s, verified %s: %s. No "+
			"technique is scored; the comment says the verdict and the counts behind it.", digest,
			st.Predicate.VerifiedAt, st.Predicate.Verdict),
		Layout: NavigatorLayout{Layout: "side", ShowID: true, ShowName: true,
			ExpandedSubtechniques: "annotated"},
		Techniques: []NavigatorTechnique{},
		LegendItems: []NavigatorLegend{
			{Label: "proven", Color: colourProven},
			{Label: "inconclusive", Color: colourInconclusive},
			{Label: "refuted", Color: colourRefuted},
			{Label: "labelled in the corpus, claimed by no rule", Color: colourUnclaimed},
		},
		Metadata: []NavigatorMetadata{
			{Name: "proof", Value: "sha256:" + digest},
			{Name: "rules", Value: "sha256:" + st.Subject[0].Digest["sha256"]},
			{Name: "verdict", Value: string(st.Predicate.Verdict)},
			{Name: "verifier", Value: st.Predicate.Verifier.ID + "/" + st.Predicate.Verifier.Version},
		},
		SelectTechniquesAcrossTactics: true, SelectSubtechniquesWithParent: false,
	}
	left := 0
	for _, t := range ev.Techniques {
		if !attackID.MatchString(t.Technique) {
			left++
			continue
		}
		colour := map[Verdict]string{Proven: colourProven, Inconclusive: colourInconclusive,
			Refuted: colourRefuted}[t.Verdict]
		comment := fmt.Sprintf("%s: %d of %d labelled instance(s) caught by a rule claiming it that raises "+
			"an alert, %d only quietly, %d missed; fired on %d of %d benign entr(ies); %d rule(s) claim it",
			t.Verdict, t.Caught, t.Positives, t.QuietOnly, t.Missed, t.FalseFires, t.Benign, len(t.Rules))
		if ev.Telemetry != nil {
			comment += fmt.Sprintf("; %d caught would not be with the fields sent lately", t.Decayed)
		}
		layer.Techniques = append(layer.Techniques, NavigatorTechnique{
			TechniqueID: t.Technique, Color: colour, Comment: comment, Enabled: true,
			Metadata: []NavigatorMetadata{
				{Name: "verdict", Value: string(t.Verdict)},
				{Name: "recall, 95% lower bound", Value: fmt.Sprintf("%.4f", t.RecallLow)},
			},
		})
	}
	for _, u := range ev.Unclaimed {
		if !attackID.MatchString(u.Technique) {
			left++
			continue
		}
		layer.Techniques = append(layer.Techniques, NavigatorTechnique{
			TechniqueID: u.Technique, Color: colourUnclaimed, Enabled: true,
			Comment: fmt.Sprintf("unclaimed: no rule claims it; %d labelled instance(s), %d caught by a rule "+
				"claiming something else", u.Positives, u.CaughtByOther),
			Metadata: []NavigatorMetadata{{Name: "verdict", Value: "unclaimed"}},
		})
	}
	doc, err := json.MarshalIndent(layer, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	return append(doc, '\n'), left, nil
}
