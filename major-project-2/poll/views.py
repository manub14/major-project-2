from django.shortcuts import render,redirect
from . import models
from .forms import InputForm
import math
from datetime import datetime
from django.contrib.admin.forms import AuthenticationForm
import time, datetime
from hashlib import sha512, sha256
from .resources import *
from .merkleTree import merkleTree
import uuid
from django.conf import settings

resultCalculated = False

# def createEvent(request):
#     if request.method == 'POST':
#         eventName = request.post.get("Event")
#         myEvent1 = models.Event(id=0,name="hasOccured",Event=eventName,count=0)
#         myEvent2 = models.Event(id=0,name="hasOccured",Event=eventName,count=0)
#         myEvent1.save()
#         myEvent2.save()
#         return render(request, 'poll/success.html')
#     else:
#         return render(request, 'poll/createEvent.html')


def createEvent(request):
	context ={}
	context['form']= InputForm()
	return render(request, "poll/createevent.html", context)


from django.shortcuts import render
from .forms import InputForm



# Create your views here.
def home_view(request):
	context ={}
	context['form']= InputForm()
	return render(request, "home.html", context)


def home(request):
    return render(request, 'poll/home.html')

def vote(request):
    candidates = models.Event.objects.all()
    context = {'candidates': candidates}
    return render(request, 'poll/vote.html', context)

def login(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            return redirect('vote')
    else:  
        form = AuthenticationForm()
    return render(request, 'poll/login.html/')

def create(request, pk):
    print(request.user)
    voter = models.Car.objects.filter(username=request.user.username)[0]

    timeElapsed = datetime.datetime.now().timestamp() - models.Vote.objects.filter(voter_public_key_n = voter.public_key_n).order_by('-timestamp')[0]


    if request.method == 'POST' and request.user.is_authenticated and not voter.has_voted and timeElapsed > minTimeForVoting :
        vote = pk
        lenVoteList = len(models.Vote.objects.all())
        if (lenVoteList > 0):
            block_id = math.floor(lenVoteList / 5) + 1
        else:
            block_id = 1

        priv_key = {'n': int(request.POST.get('privateKey_n')), 'd':int(request.POST.get('privateKey_d'))}
        pub_key = {'n':int(voter.public_key_n), 'e':int(voter.public_key_e)}
        # Create ballot as string vector
        timestamp = datetime.datetime.now().timestamp()
        ballot = "{}|{}".format(vote, timestamp)
        print('\ncasted ballot: {}\n'.format(ballot))
        h = int.from_bytes(sha512(ballot.encode()).digest(), byteorder='big')
        signature = pow(h, priv_key['d'], priv_key['n'])

        hfromSignature = pow(signature, pub_key['e'], pub_key['n'])

        if(hfromSignature == h):
            new_vote = models.Vote(vote=pk)
            new_vote.block_id = block_id
            new_vote.voter_public_key_n = voter.public_key_n
            new_vote.save()
            status = 'Ballot signed successfully'
            
            reputationConsensus()
            
            error = False
        else:
            status = 'Authentication Error'
            error = True
        context = {
            'ballot': ballot,
            'signature': signature,
            'status': status,
            'error': error,
        }
        print(error)
        if not error:
            return render(request, 'poll/status.html', context)

    return render(request, 'poll/failure.html', context)

prev_hash = '0' * 64


def reputationConsensus():
    noOfVotes = len(models.Vote.objects.all())
    if(noOfVotes % vehicleCap == 0):
        list_of_votes = models.Vote.objects.all().order_by('-timestamp')
        list_of_votes = list_of_votes[:vehicleCap]
        for vote in list_of_votes:
            candidate = models.Event.objects.filter(candidateID=vote.vote)[0]
            voter = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)[0]
            if(voter.reputation > 0.2):
                candidate.count += 1*voter.reputation
                candidate.save()
            
        verdict = models.Event.objects.order_by('count').reverse()[0]

        # filter votes for and against the poll
        for vote in list_of_votes:
            voters = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)
            if(len(voters) != 0):
                voter = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)[0]
                if(vote.vote == verdict):
                    voter.reputation += 0.05    
                else:
                    voter.reputation -= 0.1

                voter.reputation = max(0.0, voter.reputation)
                voter.reputation = min(1.0, voter.reputation)

                voter.save()



def seal(request):

    if request.method == 'POST':

        if (len(models.Vote.objects.all()) % 5 != 0):
            redirect("login")
        else:
            global prev_hash
            transactions = models.Vote.objects.order_by('block_id').reverse()
            transactions = list(transactions)[:5]
            block_id = transactions[0].block_id

            str_transactions = [str(x) for x in transactions]

            merkle_tree = merkleTree.merkleTree()
            merkle_tree.makeTreeFromArray(str_transactions)
            merkle_hash = merkle_tree.calculateMerkleRoot()

            nonce = 0
            timestamp = datetime.datetime.now().timestamp()

            while True:
                self_hash = sha256('{}{}{}{}'.format(prev_hash, merkle_hash, nonce, timestamp).encode()).hexdigest()
                if self_hash[0] == '0':
                    break
                nonce += 1
            
            block = models.Block(id=block_id,prev_hash=prev_hash,self_hash=self_hash,merkle_hash=merkle_hash,nonce=nonce,timestamp=timestamp)
            prev_hash = self_hash
            block.save()
            print('Block {} has been mined'.format(block_id))

    return redirect("home")

def retDate(v):
    v.timestamp = datetime.datetime.fromtimestamp(v.timestamp)
    return v

# VERIFY BLOCKCHAIN
def verify(request):
    if request.method == 'GET':
        verification = ''
        tampered_block_list = verifyVotes()
        votes = []
        if tampered_block_list:
            verification = 'Verification Failed. Following blocks have been tampered --> {}.\
                The authority will resolve the issue'.format(tampered_block_list)
            error = True
        else:
            verification = 'Verification successful. All votes are intact!'
            error = False
            votes = models.Vote.objects.order_by('timestamp')
            votes = [retDate(x) for x in votes]
            
        context = {'verification':verification, 'error':error, 'votes':votes}
        return render(request, 'poll/verification.html', context)

def result(request):
    if request.method == "GET":
        global resultCalculated
        voteVerification = verifyVotes()
        if len(voteVerification):
                return render(request, 'poll/verification.html', {'verification':"Verification failed.\
                Votes have been tampered in following blocks --> {}. The authority \
                    will resolve the issue".format(voteVerification), 'error':True})

        if not resultCalculated:
            list_of_votes = models.Vote.objects.all()
            for vote in list_of_votes:
                candidate = models.Event.objects.filter(candidateID=vote.vote)[0]
                
                voters = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)
                voterReputation = 1
                if(len(voters) != 0):
                    voterReputation = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)[0].reputation
                
                candidate.count += 1*voterReputation
                candidate.save()
                
            resultCalculated = True

        context = {"candidates":models.Event.objects.order_by('count'), "winner":models.Event.objects.order_by('count').reverse()[0]}
        return render(request, 'poll/results.html', context)

def verifyVotes():
    block_count = models.Block.objects.count()
    tampered_block_list = []
    for i in range (1, block_count+1):
        block = models.Block.objects.get(id=i)
        transactions = models.Vote.objects.filter(block_id=i)
        str_transactions = [str(x) for x in transactions]

        merkle_tree = merkleTree.merkleTree()
        merkle_tree.makeTreeFromArray(str_transactions)
        merkle_tree.calculateMerkleRoot()

        if (block.merkle_hash == merkle_tree.getMerkleRoot()):
            continue
        else:
            tampered_block_list.append(i)

    return tampered_block_list