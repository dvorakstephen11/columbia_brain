# todo

- Figure out how to scale the Calendar UI
    - Is it the correct way to handle displaying events? 
        - There will be hundreds or thousands of events in a month
            - I obviously don't want to display all of them as individual items. I could have a color-legend that shows event types (Family, Sports, Music, etc., and maybe an event can fall into multiple categories, although that could lead to user confusion)
                - Some filtration could be applied, but if I'm going to REPLACE that manual filtration with natural-language filtration, it seems like I should I should skip it altogether. But then again, maybe those could be separate options. Natural language processing and alerts (for new events that match a profile that the user is interested in) would only come with a subscription, but manual tag-based filtration could be free.
                    - Would need to capture filtration early, so I can see what users are interested in. If they create a filtration that 
                - Users could click a type within a day and see all the events displayed in a sort of scrolling card.
        - Maybe the user could have their own personal calendar that shows them the events they're interested in? But that feels redundant to their Google Calendar that we want to integrate with (what are the other popular calendar options that I should integrate with? Do some deep research on that.)