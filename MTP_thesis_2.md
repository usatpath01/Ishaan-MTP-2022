- Why work on this problem at all (is custom time sync required? Can you not assume vendor's clock will always be NTP synchronised? How realistic is the assumtion that NTP won't be present? If NTP is present, do you need a logical component?)
- Theoretical guarantee of your algorithm? Given a merged log file containing your timestamps, will you be able to totally order the events solely based on these timestamps?
    - What are the **ordering requirements of your envelope project**? Will partial order suffice?
- How useful is your implementation? It intercepts tcp accept and connect. Have you tried seeing what happens with keep alive HTTP connections? Or let's say in a real FaaS system (OpenWhisk, etc) docker containers communicate (if at all they do,**do they?**) with a socket conn which once opened lets the peer containers send multiple messages. You won't be able to tap these messages because there won't be tcp connect and accept involved.
- How did you test your implementation?


---

- Why not Lamport clock only?
- Why not Vector clock only?
- Why not NTP only?
- Guarantees and failure scenarios of your HLC implementation
- (IMP) HLC timestamp for each container or only one HLC per executor (this HLC timestamp represents all containers in that executor)
- challenges while implementation: intercepting a docker msg (port/xdp based filtering vs network namespace filtering)
- intercept a docker message, then wrap the executor HLC, then send the wrapped msg, on receipt unwrap, consume the received timestamp, pass orignal msg to intended container vs your proposed design 
- test it on a real life workload (using OpenWhisk, etc.)


---


See failure_scenarios folder
- failure1: 3 nodes (a,b,c), local HLC for all: 8:19, local now: 8:20 for a,c and 6:20 for b. add event for b and c, again for b, c. they're out of order. event after you send timestamp from c to b, events are ordered just once. not for subsequent events.
    - clocks are synced on receiving an event, but if the clock drifts after that, it doesn't seem possible to totally order the events in current implementation
    - you need to answer (is total ordering in a system possible)
    