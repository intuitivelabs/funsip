package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type client struct {
	apiURL string
	hc     *http.Client
}

func (c *client) get(path string) (map[string]interface{}, error) {
	resp, err := c.hc.Get(c.apiURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return result, nil
}

func (c *client) getArray(path string) ([]interface{}, error) {
	resp, err := c.hc.Get(c.apiURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(bytes.TrimSpace(body)) == 0 || string(bytes.TrimSpace(body)) == "null" {
		return nil, nil
	}
	var result []interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return result, nil
}

func (c *client) getText(path string) (string, error) {
	resp, err := c.hc.Get(c.apiURL + path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func (c *client) post(path string, body string) (map[string]interface{}, error) {
	resp, err := c.hc.Post(c.apiURL+path, "text/plain", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

func main() {
	apiURL := flag.String("api", "http://127.0.0.1:8080", "management API URL")
	refreshSec := flag.Int("refresh", 2, "refresh interval (seconds)")
	flag.Parse()

	c := &client{
		apiURL: strings.TrimRight(*apiURL, "/"),
		hc:     &http.Client{Timeout: 5 * time.Second},
	}

	app := tview.NewApplication()
	pages := tview.NewPages()

	tabs := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWrap(false)
	tabs.SetText(`  ["1"][yellow]F1: Stats[white][""]   ["2"][yellow]F2: Logs[white][""]   ["3"][yellow]F3: Registrations[white][""]   ["4"][yellow]F4: Deploy[white][""]   [white]q: Quit  r: Refresh`)
	tabs.Highlight("1")

	footer := tview.NewTextView().SetDynamicColors(true)

	statsView := buildStatsView()
	logsView := buildLogsView()
	regView := buildRegistrationsView()
	deployView, deployState := buildDeployView(c, footer)

	pages.AddPage("1", statsView, true, true)
	pages.AddPage("2", logsView, true, false)
	pages.AddPage("3", regView, true, false)
	pages.AddPage("4", deployView, true, false)

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tabs, 1, 0, false).
		AddItem(pages, 0, 1, true).
		AddItem(footer, 1, 0, false)

	currentPage := "1"

	switchTo := func(name string) {
		currentPage = name
		pages.SwitchToPage(name)
		tabs.Highlight(name)
		switch name {
		case "1":
			refreshStats(app, c, statsView, footer)
		case "2":
			refreshLogs(app, c, logsView, footer)
		case "3":
			refreshRegistrations(app, c, regView, footer)
		case "4":
			refreshDeploy(app, c, deployView, deployState, footer)
		}
	}

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyF1:
			switchTo("1")
			return nil
		case tcell.KeyF2:
			switchTo("2")
			return nil
		case tcell.KeyF3:
			switchTo("3")
			return nil
		case tcell.KeyF4:
			switchTo("4")
			return nil
		}
		switch event.Rune() {
		case '1':
			switchTo("1")
			return nil
		case '2':
			switchTo("2")
			return nil
		case '3':
			switchTo("3")
			return nil
		case '4':
			switchTo("4")
			return nil
		case 'q', 'Q':
			app.Stop()
			return nil
		case 'r', 'R':
			switchTo(currentPage)
			return nil
		}
		return event
	})

	go func() {
		ticker := time.NewTicker(time.Duration(*refreshSec) * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			switch currentPage {
			case "1":
				refreshStats(app, c, statsView, footer)
			case "2":
				refreshLogs(app, c, logsView, footer)
			case "3":
				refreshRegistrations(app, c, regView, footer)
			}
		}
	}()

	switchTo("1")

	if err := app.SetRoot(layout, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}

// ---------- Stats tab ----------

func buildStatsView() *tview.TextView {
	v := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false).
		SetScrollable(true)
	v.SetBorder(true).SetTitle(" Stats ")
	return v
}

func refreshStats(app *tview.Application, c *client, v *tview.TextView, footer *tview.TextView) {
	go func() {
		data, err := c.get("/status")
		if err != nil {
			setFooter(app, footer, fmt.Sprintf("[red]error: %v", err))
			return
		}

		txt := renderStats(data)
		app.QueueUpdateDraw(func() {
			v.SetText(txt)
			setFooterText(footer, "[green]ok ["+time.Now().Format("15:04:05")+"]")
		})
	}()
}

func renderStats(data map[string]interface{}) string {
	var b strings.Builder

	build, _ := data["build"].(map[string]interface{})
	rt, _ := data["runtime"].(map[string]interface{})
	tx, _ := data["transactions"].(map[string]interface{})
	tp, _ := data["transport"].(map[string]interface{})
	pr, _ := data["processing"].(map[string]interface{})

	fmt.Fprintf(&b, "[white::b]── General ────────────────────────────────────────────[-:-:-]\n")
	fmt.Fprintf(&b, "  [yellow]Version[white]      %v\n", data["version"])
	fmt.Fprintf(&b, "  [yellow]Build[white]        %v / %v\n", getStr(build, "vcs_revision"), getStr(build, "vcs_time"))
	fmt.Fprintf(&b, "  [yellow]Go[white]           %v\n", getStr(build, "go_version"))
	fmt.Fprintf(&b, "  [yellow]Uptime[white]       %v\n", data["uptime"])
	fmt.Fprintf(&b, "  [yellow]Goroutines[white]   %v   [yellow]GOMAXPROCS[white] %v\n", rt["goroutines"], rt["gomaxprocs"])

	fmt.Fprintf(&b, "\n[white::b]── Processing ─────────────────────────────────────────[-:-:-]\n")
	if pr != nil {
		fmt.Fprintf(&b, "  [yellow]Requests received[white]         %v\n", pr["requests_received"])
		fmt.Fprintf(&b, "  [yellow]Retransmissions received[white]  %v\n", pr["retransmissions_received"])
		fmt.Fprintf(&b, "  [yellow]Requests forwarded[white]        %v\n", pr["requests_forwarded"])
		fmt.Fprintf(&b, "  [yellow]Responses received[white]        %v\n", pr["responses_received"])
		fmt.Fprintf(&b, "  [yellow]Answered locally[white]          %v\n", pr["requests_answered_locally"])

		if cls, ok := pr["responses_by_class"].(map[string]interface{}); ok {
			fmt.Fprintf(&b, "\n  [yellow]Responses by class[white]\n")
			for _, k := range []string{"1xx", "2xx", "3xx", "4xx", "5xx", "6xx"} {
				fmt.Fprintf(&b, "    %s   %v\n", k, cls[k])
			}
		}

		fmt.Fprintf(&b, "\n  [yellow]Avg processing delay[white]\n")
		fmt.Fprintf(&b, "    last 5 min   %v ms\n", pr["avg_delay_5m_ms"])
		fmt.Fprintf(&b, "    last 1 hour  %v ms\n", pr["avg_delay_1h_ms"])

		fmt.Fprintf(&b, "\n  [yellow]Request rate[white]\n")
		fmt.Fprintf(&b, "    last 5 min   %.2f req/s\n", getFloat(pr, "request_rate_5m_per_sec"))
		fmt.Fprintf(&b, "    last 1 hour  %.2f req/s\n", getFloat(pr, "request_rate_1h_per_sec"))
	}

	fmt.Fprintf(&b, "\n[white::b]── Transactions ───────────────────────────────────────[-:-:-]\n")
	if tx != nil {
		fmt.Fprintf(&b, "  [yellow]Total created[white]        %v\n", tx["total_created"])
		fmt.Fprintf(&b, "  [yellow]Active[white]               %v   ([yellow]server[white] %v / [yellow]client[white] %v)\n",
			tx["active"], tx["server_count"], tx["client_count"])
		fmt.Fprintf(&b, "  [yellow]Pending INVITE[white]       %v\n", tx["pending_invite"])
		fmt.Fprintf(&b, "  [yellow]Pending non-INVITE[white]   %v\n", tx["pending_non_invite"])
		fmt.Fprintf(&b, "  [yellow]Avg client tx time[white]   %v ms\n", tx["avg_resp_time_ms"])
	}

	fmt.Fprintf(&b, "\n[white::b]── Transport ──────────────────────────────────────────[-:-:-]\n")
	if tp != nil {
		fmt.Fprintf(&b, "  [yellow]UDP[white]   in: %-8v   out: %v\n", tp["udp_received"], tp["udp_sent"])
		fmt.Fprintf(&b, "  [yellow]TCP[white]   in: %-8v   out: %v\n", tp["tcp_received"], tp["tcp_sent"])
		fmt.Fprintf(&b, "  [yellow]Parse errors[white]  %v\n", tp["parse_errors"])
	}

	return b.String()
}

// ---------- Logs tab ----------

func buildLogsView() *tview.TextView {
	v := tview.NewTextView().
		SetDynamicColors(false).
		SetWrap(false).
		SetScrollable(true)
	v.SetBorder(true).SetTitle(" Logs (ringbuffer) ")
	return v
}

func refreshLogs(app *tview.Application, c *client, v *tview.TextView, footer *tview.TextView) {
	go func() {
		entries, err := c.getArray("/logs")
		if err != nil {
			setFooter(app, footer, fmt.Sprintf("[red]error: %v", err))
			return
		}

		var b strings.Builder
		for _, e := range entries {
			m, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			ts := getStr(m, "timestamp")
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				ts = t.Format("15:04:05.000")
			}
			msg := strings.TrimRight(getStr(m, "message"), "\n")
			fmt.Fprintf(&b, "%s %s\n", ts, msg)
		}

		app.QueueUpdateDraw(func() {
			v.SetText(b.String())
			v.ScrollToEnd()
			setFooterText(footer, fmt.Sprintf("[green]%d log entries [%s]", len(entries), time.Now().Format("15:04:05")))
		})
	}()
}

// ---------- Registrations tab ----------

func buildRegistrationsView() *tview.Table {
	t := tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	t.SetBorder(true).SetTitle(" Active Registrations ")
	return t
}

func refreshRegistrations(app *tview.Application, c *client, t *tview.Table, footer *tview.TextView) {
	go func() {
		regs, err := c.getArray("/registrations")
		if err != nil {
			setFooter(app, footer, fmt.Sprintf("[red]error: %v", err))
			return
		}

		app.QueueUpdateDraw(func() {
			t.Clear()
			headers := []string{"AOR", "Contact", "Received", "Transport", "Expires", "User-Agent"}
			for col, h := range headers {
				t.SetCell(0, col, tview.NewTableCell(h).
					SetTextColor(tcell.ColorYellow).
					SetSelectable(false).
					SetAttributes(tcell.AttrBold))
			}

			for row, e := range regs {
				m, ok := e.(map[string]interface{})
				if !ok {
					continue
				}
				received := fmt.Sprintf("%s:%v", getStr(m, "received_ip"), m["received_port"])
				expiresAt := getStr(m, "expires_at")
				if t2, err := time.Parse(time.RFC3339, expiresAt); err == nil {
					expiresAt = fmt.Sprintf("%s (%s)", t2.Format("15:04:05"), shortDuration(time.Until(t2)))
				}
				cells := []string{
					getStr(m, "aor"),
					getStr(m, "contact"),
					received,
					getStr(m, "transport"),
					expiresAt,
					getStr(m, "user_agent"),
				}
				for col, s := range cells {
					t.SetCell(row+1, col, tview.NewTableCell(s))
				}
			}

			setFooterText(footer, fmt.Sprintf("[green]%d registrations [%s]", len(regs), time.Now().Format("15:04:05")))
		})
	}()
}

// ---------- Deploy tab ----------

type deploySt struct {
	mu       sync.Mutex
	original string
}

func buildDeployView(c *client, footer *tview.TextView) (*tview.Flex, *deploySt) {
	state := &deploySt{}

	editor := tview.NewTextArea()
	editor.SetBorder(true).SetTitle(" Routing script (edit and press Ctrl-D to deploy) ")

	hint := tview.NewTextView().
		SetDynamicColors(true).
		SetText("  [yellow]Ctrl-D[white]: Deploy   [yellow]Ctrl-R[white]: Rollback   [yellow]Ctrl-L[white]: Reload from server")

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(editor, 0, 1, true).
		AddItem(hint, 1, 0, false)

	editor.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyCtrlD:
			deployScript(c, editor, footer, state)
			return nil
		case tcell.KeyCtrlR:
			rollbackScript(c, editor, footer, state)
			return nil
		case tcell.KeyCtrlL:
			loadScript(c, editor, footer, state)
			return nil
		}
		return event
	})

	return flex, state
}

func refreshDeploy(app *tview.Application, c *client, _ *tview.Flex, state *deploySt, footer *tview.TextView) {
	go func() {
		text, err := c.getText("/script")
		if err != nil {
			setFooter(app, footer, fmt.Sprintf("[red]error loading script: %v", err))
			return
		}
		state.mu.Lock()
		alreadyLoaded := state.original != ""
		state.original = text
		state.mu.Unlock()

		app.QueueUpdateDraw(func() {
			if !alreadyLoaded {
				if ed := findEditor(app); ed != nil {
					ed.SetText(text, true)
				}
			}
			setFooterText(footer, fmt.Sprintf("[green]script loaded (%d bytes) [%s]", len(text), time.Now().Format("15:04:05")))
		})
	}()
}

func findEditor(app *tview.Application) *tview.TextArea {
	root := app.GetFocus()
	if ed, ok := root.(*tview.TextArea); ok {
		return ed
	}
	return nil
}

func loadScript(c *client, editor *tview.TextArea, footer *tview.TextView, state *deploySt) {
	go func() {
		text, err := c.getText("/script")
		if err != nil {
			setFooterText(footer, fmt.Sprintf("[red]load error: %v", err))
			return
		}
		state.mu.Lock()
		state.original = text
		state.mu.Unlock()
		editor.SetText(text, true)
		setFooterText(footer, fmt.Sprintf("[green]script reloaded from server (%d bytes)", len(text)))
	}()
}

func deployScript(c *client, editor *tview.TextArea, footer *tview.TextView, state *deploySt) {
	go func() {
		body := editor.GetText()
		result, err := c.post("/deploy", body)
		if err != nil {
			setFooterText(footer, fmt.Sprintf("[red]deploy network error: %v", err))
			return
		}
		if result["success"] == true {
			state.mu.Lock()
			state.original = body
			state.mu.Unlock()
			setFooterText(footer, fmt.Sprintf("[green]deployed (%d bytes) — Ctrl-R to rollback", len(body)))
		} else {
			setFooterText(footer, fmt.Sprintf("[red]deploy failed: %v", result["error"]))
		}
	}()
}

func rollbackScript(c *client, editor *tview.TextArea, footer *tview.TextView, state *deploySt) {
	go func() {
		result, err := c.post("/rollback", "")
		if err != nil {
			setFooterText(footer, fmt.Sprintf("[red]rollback network error: %v", err))
			return
		}
		if result["success"] == true {
			text, _ := c.getText("/script")
			state.mu.Lock()
			state.original = text
			state.mu.Unlock()
			editor.SetText(text, true)
			setFooterText(footer, "[green]rolled back to previous script")
		} else {
			setFooterText(footer, fmt.Sprintf("[red]rollback failed: %v", result["error"]))
		}
	}()
}

// ---------- Helpers ----------

func setFooter(app *tview.Application, footer *tview.TextView, text string) {
	app.QueueUpdateDraw(func() {
		setFooterText(footer, text)
	})
}

func setFooterText(footer *tview.TextView, text string) {
	footer.SetText("  " + text)
}

func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func getFloat(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func shortDuration(d time.Duration) string {
	if d < 0 {
		return "expired"
	}
	if d > 24*time.Hour {
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	}
	if d > time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	if d > time.Minute {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
