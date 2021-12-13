// Copyright (c) 2021 Shivaram Lingamneni
// Released under the MIT License

package main

// ghbot is a simple bot that listens via HTTP for GitHub webhook events,
// then announces them to an IRC channel.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ergochat/irc-go/ircevent"
	"github.com/ergochat/irc-go/ircmsg"
	"github.com/ergochat/irc-go/ircutils"
	"github.com/google/go-github/v41/github"
)

const (
	// https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads
	// "Note: Payloads are capped at 25 MB. If your event generates a larger payload,
	// a webhook will not be fired."
	// we can't validate the request's signature until we've read the entire body,
	// so stop reading after 25MB so non-GitHub requests can't DoS us:
	readLimit = 25 * 1024 * 1024

	httpTimeout = 30 * time.Second

	ircMessageMaxPayload = 400

	commentTextLimitBytes = 200

	maxCommits = 3
)

var (
	httpClient = &http.Client{
		Timeout: 15 * time.Second,
	}
)

func isGithubURL(url_ string) bool {
	return strings.HasPrefix(url_, "https://github.com/") || strings.HasPrefix(url_, "https://www.github.com/")
}

// simple client for the git.io shortener
func shortenURL(url_ string) (result string) {
	result = url_
	// if this a selfhosted gogs or gitea, don't attempt to shorten:
	if !isGithubURL(url_) {
		return
	}
	resp, err := httpClient.PostForm("https://git.io", url.Values{
		"url": {url_},
	})
	if err != nil {
		log.Printf("couldn't shorten %s: %v\n", url_, err)
		return
	}
	short := resp.Header.Get("Location")
	if short != "" {
		result = short
	}
	return
}

func verifyHmacSha256(msg, sig, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	truesig := mac.Sum(nil)
	return hmac.Equal(truesig, sig)
}

type Bot struct {
	ircevent.Connection
	Channel          string
	GHSignatureToken []byte
	GLStaticToken    []byte
	UsePrivmsg       bool
	Debug            bool
}

func (bot *Bot) announce(message string) {
	text := ircutils.SanitizeText(message, ircMessageMaxPayload)
	if bot.UsePrivmsg {
		bot.Privmsg(bot.Channel, text)
	} else {
		bot.Notice(bot.Channel, text)
	}
}

var (
	signatureHeaders = []string{"X-Hub-Signature-256", "X-Gogs-Signature", "X-Gitea-Signature"}
	msgTypeHeaders   = []string{"X-Github-Event", "X-Gogs-Event", "X-Gitea-Event"}
)

func extractHeaders(headers http.Header) (msgType string, signature []byte, gitlabToken string, err error) {
	tryAllHeaders := func(headers http.Header, names []string) (result string) {
		for _, name := range names {
			if val := headers.Get(name); val != "" {
				return val
			}
		}
		return
	}
	rawSignature := tryAllHeaders(headers, signatureHeaders)
	if rawSignature != "" {
		rawSignature = strings.TrimPrefix(rawSignature, "sha256=")
		signature, err = hex.DecodeString(rawSignature)
	}
	msgType = strings.ToLower(tryAllHeaders(headers, msgTypeHeaders))
	gitlabToken = headers.Get("X-Gitlab-Token")
	return
}

type messageHandler func(msgType string, body []byte)

// implements http.Handler
func (bot *Bot) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic encountered: %v\n%s", r, debug.Stack())
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()

	msgType, signature, gitlabToken, err := extractHeaders(req.Header)
	if err != nil {
		log.Printf("error reading headers: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if bot.GLStaticToken != nil {
		if gitlabToken == "" {
			log.Printf("ignoring request without required GitLab static token\n")
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if !hmac.Equal([]byte(gitlabToken), bot.GLStaticToken) {
			log.Printf("ignoring request with incorrect GitLab static token\n")
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else if len(signature) == 0 {
		log.Printf("ignoring request without required signature token\n")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var handler messageHandler
	switch msgType {
	case "ping":
		handler = bot.processPing
	case "create", "delete":
		handler = bot.processGitCreateDelete
	case "commit_comment":
		handler = bot.processCommitComment
	case "issue_comment":
		handler = bot.processIssueComment
	case "issues":
		handler = bot.processIssues
	case "push":
		handler = bot.processPush
	case "pull_request":
		handler = bot.processPullRequest
	case "pull_request_review":
		handler = bot.processPullRequestReview
	case "pull_request_review_comment":
		// TODO figure out how to display at most 1 or 2 of these
		// per pull_request_review event
	case "workflow_run":
		handler = bot.processWorkflowRun
	}

	// always read the body even if handler is nil;
	// nginx gets unhappy if you close the connection while it's still
	// trying to send the POST body, sometimes this can even cause a 502

	l := io.LimitedReader{R: req.Body, N: readLimit}
	body, err := io.ReadAll(&l)
	if err != nil {
		log.Printf("error reading response body from %s: %v\n", req.RemoteAddr, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// if it's GitLab, we already verified the static token, otherwise
	// we need a signature check:
	if bot.GLStaticToken == nil && !verifyHmacSha256(body, signature, bot.GHSignatureToken) {
		log.Printf("invalid HMAC signature from %s\n", req.RemoteAddr)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if bot.Debug {
		log.Printf("received %s: %s\n", msgType, body)
	}
	if handler != nil {
		handler(msgType, body)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (bot *Bot) processPing(msgType string, body []byte) {
	var evt github.PingEvent
	err := json.Unmarshal(body, &evt)
	if err != nil {
		log.Printf("invalid JSON for %s: %v\n", msgType, err)
		return
	}
	url := "n/a"
	if evt.Hook != nil && evt.Hook.URL != nil {
		url = *evt.Hook.URL
	}
	log.Printf("successfully authenticated ping from %s", url)
}

func (bot *Bot) processWorkflowRun(msgType string, body []byte) {
	var evt github.WorkflowRunEvent
	err := json.Unmarshal(body, &evt)
	if err != nil {
		log.Printf("invalid JSON for %s: %v\n", msgType, err)
		return
	}
	if *evt.Action != "completed" {
		return
	}
	// TODO ignore successes for now, other users may want different behavior
	if *evt.WorkflowRun.Conclusion == "success" {
		return
	}
	_, message := extractAuthorMessage(*evt.WorkflowRun.HeadCommit)
	bot.announce(fmt.Sprintf("%s/%s: workflow for commit %s (\"%s\") finished with status %s: %s",
		*evt.Repo.Owner.Login, *evt.Repo.Name,
		(*evt.WorkflowRun.HeadCommit.ID)[:12], message,
		strings.ToUpper(*evt.WorkflowRun.Conclusion),
		shortenURL(*evt.WorkflowRun.HTMLURL),
	))
}

func (bot *Bot) processGitCreateDelete(msgType string, body []byte) {
	// all relevant fields are shared between CreateEvent and DeleteEvent
	var evt github.CreateEvent
	err := json.Unmarshal(body, &evt)
	if err != nil {
		log.Printf("invalid JSON for %s: %v\n", msgType, err)
		return
	}
	action := "created"
	if msgType == "delete" {
		action = "deleted"
	}
	bot.announce(fmt.Sprintf("%s/%s: %s %s %s %s",
		*evt.Repo.Owner.Login, *evt.Repo.Name,
		*evt.Sender.Login, action, *evt.RefType, *evt.Ref))
}

func truncateComment(comment string) (result string) {
	result = ircutils.TruncateUTF8Safe(comment, commentTextLimitBytes)
	if len(result) < len(comment) {
		result = fmt.Sprintf("%s[...]", result)
	}
	return
}

func (bot *Bot) processCommitComment(msgType string, body []byte) {
	var evt github.CommitCommentEvent
	err := json.Unmarshal(body, &evt)
	if err != nil {
		log.Printf("invalid JSON for %s: %v\n", msgType, err)
		return
	}
	bot.announce(fmt.Sprintf("%s/%s: %s commented on commit %s: \"%s\" %s",
		*evt.Repo.Owner.Login, *evt.Repo.Name,
		*evt.Comment.User.Login, (*evt.Comment.CommitID)[:8],
		truncateComment(*evt.Comment.Body),
		shortenURL(*evt.Comment.HTMLURL),
	))
}

func (bot *Bot) processPullRequest(msgType string, body []byte) {
	var evt github.PullRequestEvent
	err := json.Unmarshal(body, &evt)
	if err != nil {
		log.Printf("invalid JSON for %s: %v\n", msgType, err)
		return
	}
	action := *evt.Action
	// https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads#pull_request
	var description string
	switch action {
	case "assigned", "closed", "edited", "reopened", "unassigned":
		// ok
	case "opened":
		description = fmt.Sprintf("\"%s\" ", truncateComment(*evt.PullRequest.Body))
	case "synchronize":
		// "Triggered when a pull request's head branch is updated." lol
		action = "updated"
	default:
		// ignore "labeled", "milestoned", a few others
		return
	}
	bot.announce(fmt.Sprintf("%s/%s: %s %s pull request #%d (%s): %s%s",
		*evt.Repo.Owner.Login, *evt.Repo.Name,
		*evt.PullRequest.User.Login, action, *evt.PullRequest.Number, *evt.PullRequest.Title,
		description, shortenURL(*evt.PullRequest.HTMLURL),
	))
}

func (bot *Bot) processPullRequestReview(msgType string, body []byte) {
	var evt github.PullRequestReviewEvent
	err := json.Unmarshal(body, &evt)
	if err != nil {
		log.Printf("invalid JSON for %s: %v\n", msgType, err)
		return
	}
	bot.announce(fmt.Sprintf("%s/%s: %s reviewed pull request #%d (%s): %s",
		*evt.Repo.Owner.Login, *evt.Repo.Name,
		*evt.Review.User.Login, *evt.PullRequest.Number, *evt.PullRequest.Title,
		shortenURL(*evt.Review.HTMLURL),
	))
}

func (bot *Bot) processIssues(msgType string, body []byte) {
	var evt github.IssuesEvent
	err := json.Unmarshal(body, &evt)
	if err != nil {
		log.Printf("invalid JSON for %s: %v\n", msgType, err)
		return
	}
	action := *evt.Action
	var description string
	switch action {
	case "opened":
		description = fmt.Sprintf("\"%s\" ", truncateComment(*evt.Issue.Body))
	case "edited", "deleted", "closed", "reopened", "assigned", "unassigned":
		// ok
	default:
		// ignore "labeled", "milestoned", a few others
		return
	}
	bot.announce(fmt.Sprintf("%s/%s: %s %s issue #%d (%s): %s%s",
		*evt.Repo.Owner.Login, *evt.Repo.Name,
		*evt.Sender.Login, *evt.Action, *evt.Issue.Number, *evt.Issue.Title,
		description, shortenURL(*evt.Issue.HTMLURL)))
}

func (bot *Bot) processIssueComment(msgType string, body []byte) {
	var evt github.IssueCommentEvent
	err := json.Unmarshal(body, &evt)
	if err != nil {
		log.Printf("invalid JSON for %s: %v\n", msgType, err)
		return
	}
	bot.announce(fmt.Sprintf("%s/%s: %s commented on #%d (%s): \"%s\" %s",
		*evt.Repo.Owner.Login, *evt.Repo.Name,
		*evt.Comment.User.Login, *evt.Issue.Number, *evt.Issue.Title,
		truncateComment(*evt.Comment.Body),
		shortenURL(*evt.Comment.HTMLURL),
	))
}

func extractAuthorMessage(commit github.HeadCommit) (author, message string) {
	lines := strings.Split(*commit.Message, "\n")
	message = lines[0]
	if commit.Author.Login != nil {
		author = *commit.Author.Login
	} else {
		author = *commit.Author.Email
	}
	return
}

func (bot *Bot) processPush(msgType string, body []byte) {
	var evt github.PushEvent
	err := json.Unmarshal(body, &evt)
	if err != nil {
		log.Printf("invalid JSON for push: %v\n", err)
		return
	}
	ref := "n/a"
	if evt.Ref != nil {
		ref = *evt.Ref
	}
	username := "n/a"
	if evt.Pusher.Name != nil {
		username = *evt.Pusher.Name
	} else if evt.Pusher.Login != nil {
		// gogs publishes 'username' and 'login' but not 'name':
		username = *evt.Pusher.Login
	}
	commits := evt.Commits
	if len(commits) == 0 {
		return
	}
	if len(commits) == 1 {
		bot.announce(fmt.Sprintf("%s/%s: %s pushed a commit to %s: %s",
			*evt.Repo.Owner.Login, *evt.Repo.Name,
			username, ref,
			bot.describeCommit(*commits[0]),
		))
		return
	}
	bot.announce(fmt.Sprintf("%s/%s: %s pushed %d commit(s) to %s",
		*evt.Repo.Owner.Login, *evt.Repo.Name,
		username, len(evt.Commits), ref))
	// grace of 1, since we'd have to display a "commits omitted" message anyway
	omitted := len(commits) - maxCommits
	if omitted > 1 {
		commits = commits[len(commits)-maxCommits:]
	}
	for _, commit := range commits {
		bot.announce(bot.describeCommit(*commit))
	}
	if omitted > 1 {
		bot.announce(fmt.Sprintf("+%d hidden commit(s)", omitted))
	}
}

func (bot *Bot) describeCommit(commit github.HeadCommit) string {
	author, message := extractAuthorMessage(commit)
	return fmt.Sprintf("%s [%s]: \"%s\" %s",
		(*commit.ID)[:12], author, message, shortenURL(*commit.URL),
	)
}

func newBot() (bot *Bot, err error) {
	// required:
	nick := os.Getenv("GHBOT_NICK")
	server := os.Getenv("GHBOT_SERVER")
	httpaddr := os.Getenv("GHBOT_LISTEN_ADDR")
	var ghSignatureToken, glStaticToken []byte
	if ghTokenStr := os.Getenv("GHBOT_GITHUB_SECRET_TOKEN"); ghTokenStr != "" {
		// HMAC-SHA256 signature token, used by GitHub, Gogs, Gitea:
		ghSignatureToken = []byte(ghTokenStr)
	} else if glTokenStr := os.Getenv("GHBOT_GITLAB_SECRET_TOKEN"); glTokenStr != "" {
		// static token, used by Gitlab:
		glStaticToken = []byte(glTokenStr)
	} else {
		return nil, fmt.Errorf("you must export either GHBOT_GITHUB_SECRET_TOKEN or GHBOT_GITLAB_SECRET_TOKEN")
	}
	channel := os.Getenv("GHBOT_CHANNEL")
	// SASL is optional:
	saslLogin := os.Getenv("GHBOT_SASL_LOGIN")
	saslPassword := os.Getenv("GHBOT_SASL_PASSWORD")
	// more optional settings
	version := os.Getenv("GHBOT_VERSION")
	if version == "" {
		version = "github.com/ergochat/irc-go"
	}
	debug := os.Getenv("GHBOT_DEBUG") != ""
	insecure := os.Getenv("GHBOT_INSECURE_SKIP_VERIFY") != ""
	usePrivmsg := os.Getenv("GHBOT_USE_PRIVMSG") != ""

	var listener net.Listener
	httpaddr = strings.TrimPrefix(httpaddr, "unix:")
	if strings.HasPrefix(httpaddr, "/") {
		os.Remove(httpaddr)
		listener, err = net.Listen("unix", httpaddr)
		if err == nil {
			os.Chmod(httpaddr, 0777)
		}
	} else {
		listener, err = net.Listen("tcp", httpaddr)
	}
	if err != nil {
		return
	}

	var tlsconf *tls.Config
	if insecure {
		tlsconf = &tls.Config{InsecureSkipVerify: true}
	}
	bot = &Bot{
		Connection: ircevent.Connection{
			Server:       server,
			Nick:         nick,
			UseTLS:       true,
			TLSConfig:    tlsconf,
			SASLLogin:    saslLogin, // SASL will be enabled automatically if these are set
			SASLPassword: saslPassword,
			QuitMessage:  version,
			Debug:        debug,
		},
		Channel:          channel,
		GHSignatureToken: ghSignatureToken,
		GLStaticToken:    glStaticToken,
		Debug:            debug,
		UsePrivmsg:       usePrivmsg,
	}

	bot.AddConnectCallback(func(e ircmsg.Message) {
		bot.Join(strings.TrimSpace(channel))
	})

	hServer := http.Server{
		Handler:        bot,
		ReadTimeout:    httpTimeout,
		WriteTimeout:   httpTimeout,
		MaxHeaderBytes: 1024 * 1024,
	}

	go func() {
		err := hServer.Serve(listener)
		log.Printf("HTTP server closed: %v\n", err)
	}()

	return bot, nil
}

func main() {
	irc, err := newBot()
	if err != nil {
		log.Fatal(err)
	}
	err = irc.Connect()
	if err != nil {
		log.Fatal(err)
	}
	irc.Loop()
}
