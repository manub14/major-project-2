from django import forms
from .models import createevent



class InputForm(forms.Form):
    first_name = forms.CharField(max_length=200)
    candidate_id = forms.IntegerField()
    event_choices = [('accident', 'Accident'), ('congestion', 'Congestion'), ('road-block', 'Road-Block')]
    event = forms.ChoiceField(choices=event_choices, initial='congestion', widget=forms.RadioSelect)
    count = forms.IntegerField(help_text="Enter count of event")


    
