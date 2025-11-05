# todo

Recent updates
- Auth flow lives on dedicated routes (`/login`, `/register`, `/verify`, `/username-setup`); mock verification codes appear in dev responses and the account menu exposes shortcuts to finish sign-up.
PHASE ONE: MVP
- DB + Auth + User Profile
- Improve Calendar UI
- Scraping
- FTS
- RAG
- Knowledge Graphs
- SMTP
- Stripe (??? Or phase 2?)
- Legal basics (privacy policy, terms of service, etc.)
- MVP  (Mid-February?)

PHASE TWO:
- Alert feature
- Marketing
- $10/mo subscription
- News
    - Scrape Maury County and City of Columbia website for meeting files (text, video, audio, pictures)
- 10 paying customers by 2026-04-24 (JESUS BIRTHDAY)

PHASE THREE:
- Directory
- MASSIVE scraping improvement + deployment


PHASE FOUR:
- Games
- Socials
- Church stuff?


PHASE FIVE:
- Business subscription (market trends)


PHASE SIX:
- IoT


PHASE SEVEN: EXPAND
- Expand to one other location
    - Spring Hill? 
        - Or maybe Spring Hill is already covered by Maury County
    - Mount Pleasant?
        - Or maybe Mount Pleasant is already covered by Maury County
    - Franklin?
    - Murfreesboro?
- Primary difficulty is in scaling the data infrastructure for processing all the extra data.

PHASE EIGHT: EXPLODE
- Expand to two additional locations
    - Nashville
    - Brentwood
    
PHASE NINE: CONQUER EVERYTHING
- Expand to five additional locations
    - Chattanooga
    - Memphis
    - Clarksville
    - Dickson
    - Knoxville


- Figure out how to scale the Calendar UI
    - Is it the correct way to handle displaying events? 
        - There will be hundreds or thousands of events in a month
            - I obviously don't want to display all of them as individual items. I could have a color-legend that shows event types (Family, Sports, Music, etc., and maybe an event can fall into multiple categories, although that could lead to user confusion)
                - Some filtration could be applied, but if I'm going to REPLACE that manual filtration with natural-language filtration, it seems like I should I should skip it altogether. But then again, maybe those could be separate options. Natural language processing and alerts (for new events that match a profile that the user is interested in) would only come with a subscription, but manual tag-based filtration could be free.
                    - Would need to capture filtration early, so I can see what users are interested in. If they create a filtration that 
                - Users could click a type within a day and see all the events displayed in a sort of scrolling card.
        - Maybe the user could have their own personal calendar that shows them the events they're interested in? But that feels redundant to their Google Calendar that we want to integrate with (what are the other popular calendar options that I should integrate with? Do some deep research on that.)

- Build out a personal workflow where I investigate the codebase using AI
    - Copy this section of notes when it's all fleshed out into GPT-5-Thinking-Heavy and ask it to suggest which other questions I should periodically ask.
    - Copy the codebase to the Columbia Cooperative Project Files (overwrite the existing file, if it exists) and ask some common questions about the codebase (this should be done periodically to ensure I retain )
        - Are there any design patterns that are exhibited by the frontend code in this codebase? If so, what are those patterns, what are the tradeoffs of using them, and what are the alternatives? I'm especially interested in weighing the application speed, codebase complexity, codebase maintainability, codebase scalability, security, and user experience.
        - What are the least secure parts of my codebase?
        - What are the least maintainable parts of my codebase?
        - What are the least scalable parts of my codebase?
        - Are there any aspects to the architecture of my codebase that seem at odds with the apparent purpose of the application?
        - What are the main gaps in testing? What kind of testing is the best to use for my particular application?
        - Based upon my codebase below, including the README.md that describes my usage of Render, what level of coupling is there between my application and Render, and how difficult do you think it would be to migrate my application to a different hosting platform?
            - Make this one of the common factors in decision analysis when G5P is asked design questions.

- Figure out a marketing strategy
    - Looking for a low-cost, high-impact marketing strategy, perhaps utilizing Google Ads for people who search things like "things to do in Columbia"
    - Pick beta customers
        - Ashley Dvorak (obvs)
            - Introduce it to her when a fully functioning website is ready (including a promo code that gives her a lifetime subscription for free)
        - Danny Coleman
        - Brandon Blalock
        - Taylor Lord (let's see if he suggests it to Anna)
        - Josh Owens (can get his opinion on the website from the perspective of a professional web developer)
        - Lance (FussyFriendNachos on Reddit)
        - Dad? (nah, not for beta)


- Figure out how to incorporate my positivesumtechnologies.com domain
     - Maybe I need to buy another domain


    
