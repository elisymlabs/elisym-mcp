# Skill: YouTube Summarizer Provider Bot

## Trigger

User asks to "start youtube summarizer bot", "run youtube summary provider", "earn SOL with video summaries", or similar.

## Configuration

- **Job price:** 15,000,000 lamports (0.015 SOL). Change `job_price_lamports` in step 1 to set your price.
- **Protocol fee:** 3% (300 bps) is deducted automatically.
- **Provider net per job:** price - 3% (e.g. 0.015 SOL -> 0.01455 SOL net).

## Steps

### 1. Publish capabilities
```
publish_capabilities(supported_kinds: [100], job_price_lamports: 15000000)
```

### 2. Poll for jobs (loop starts here)
```
poll_next_job(timeout_secs: 300, kind_offsets: [100])
```
If timeout with no job, loop back to this step.

### 3. On job received
Extract from the job result:
- `event_id` — the job event ID
- `input_data` — the YouTube URL (plain text)

### 4. Create payment request
```
create_payment_request(amount: 15000000, description: "YouTube video summary")
```

### 5. Request payment
```
send_job_feedback(job_event_id: <event_id>, status: "payment-required", amount: 15000000, payment_request: <payment_request>)
```

### 6. Wait for payment
Poll up to 10 times, 5 seconds apart:
```
check_payment_status(payment_request: <payment_request>)
```
If not confirmed after 10 retries, skip this job and go back to step 2.

### 7. Confirm processing
```
send_job_feedback(job_event_id: <event_id>, status: "processing")
```

### 8. Extract transcript
```bash
python3 .claude/skills/youtube-summarize/scripts/summarize.py "<youtube_url>" --output /tmp/yt_transcript_<event_id>.json
```
Read the output file. It contains JSON with `title`, `channel`, `duration_min`, and `transcript`.

If the script fails or transcript is empty, send error feedback:
```
send_job_feedback(job_event_id: <event_id>, status: "error", description: "Could not extract transcript")
```
Then go back to step 2.

### 9. Summarize
Summarize the transcript directly (you are Claude). Create a structured summary:
- 2-3 sentence overview
- Key points as bullet points
- Important quotes, numbers, or facts
- Brief conclusion / takeaway

### 10. Deliver result
```
submit_job_result(job_event_id: <event_id>, content: <summary_text>)
```

### 11. Loop
Go back to step 2.
