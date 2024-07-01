
from openai import OpenAI
import json
import time
import sys
MATH_ASSISTANT_ID = "asst_mv12OpTEVY7v1TPnH8O6sRIR"  # or a hard-coded ID like "asst-..."

client = OpenAI(api_key="sk-xTu27uuR0xee8cD46BG")
thread = client.beta.threads.create()
cve = sys.argv[1]
run = client.beta.threads.runs.create(
    thread_id=thread.id,
    assistant_id="asst_mv12x6sRIR",
)


def submit_message(assistant_id, thread, user_message):
    client.beta.threads.messages.create(
        thread_id=thread.id, role="user", content=user_message
    )
    return client.beta.threads.runs.create(
        thread_id=thread.id,
        assistant_id=assistant_id,
    )


def get_response(thread):
    return client.beta.threads.messages.list(thread_id=thread.id, order="asc")

def wait_on_run(run, thread):
    start_time = time.time()  # Capture start time
    while run.status == "queued" or run.status == "in_progress":
        run = client.beta.threads.runs.retrieve(
            thread_id=thread.id,
            run_id=run.id,
        )
        time.sleep(0.5)
    end_time = time.time()  # Capture end time
    duration = end_time - start_time  # Calculate duration
   # Print duration
    return run

def pretty_print(messages):
    print("# Messages")
    for m in messages:
        print(f"{m.role}: {m.content[0].text.value}")
    print()

def create_thread_and_run(user_input):
    thread = client.beta.threads.create()
    run = submit_message(MATH_ASSISTANT_ID, thread, user_input)
    return thread, run


thread, run = create_thread_and_run(
      f'"Please provide the JSON data for {cve} with the following format: '
    '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>"}."'
)

run = wait_on_run(run, thread)
pretty_print(get_response(thread))



# run = wait_on_run(run, thread)
# messages = client.beta.threads.messages.list(thread_id=thread.id)
#print(messages.data[0].content[0].text.value)
# def show_json(obj):
#     display(json.loads(obj.model_dump_json()))

# def submit_message(assistant_id, thread, user_message):
#     client.beta.threads.messages.create(
#         thread_id=thread.id, role="user", content=user_message
#     )
#     return client.beta.threads.runs.create(
#         thread_id=thread.id,
#         assistant_id=assistant_id,
#     )


# def get_response(thread):
#     return client.beta.threads.messages.list(thread_id=thread.id, order="asc")