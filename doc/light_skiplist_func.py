#DistanceSkipList
def distance_skip_list(start, n)
    result = (0, start) #initial_solution
    pos = start

    def get_delta(element):
        return element, 1, self.previous(element)

    while True:
        if not (result[0] == n):
            delta = get_delta(result[1])
            result = (result[0] + delta[1], delta[2])
            pos = self.previous(element)
        else:
            break

#WeightsSkipList
def weights_skip_list(start, max_shares, desired_weight):
    result = (0, None, 0, 0) #initial_solution
    pos = start

    def get_delta(element):
        from p2pool.bitcoin import data as bitcoin_data
        share = self.tracker.items[element]
        att = bitcoin_data.target_to_average_attempts(share.target)
        #(share_count2, weights2, total_weight2, total_donation_weight2)
        # share_count2 = 1,
        # weights2 = {share.new_script: att*(65535-share.share_data['donation'])},
        # total_weight2 = att*65535,
        # total_donation_weight2 = att*share.share_data['donation']
        return 1, {share.new_script: att*(65535-share.share_data['donation'])}, att*65535, att*share.share_data['donation']

    while True:
        if not (result[0] == max_shares or result[2] == desired_weight):
            delta = get_delta(pos)
            
            if result[2] + delta[2] > desired_weight and delta[0] == 1:
                assert (desired_weight - result[2]) % 65535 == 0
                script, = delta[1].iterkeys()
                new_weights = {script: (desired_weight - result[3])//65535*result[1][script]//(result[2]//65535)}
                result = (result[0] + delta[0], (result[1], new_weights), desired_weight, result[3] + (desired_weight - result[2])//65535*delta[3]//(delta[2]//65535))
            else:
                result = (result[0] + delta[0], (result[1], delta[1]), result[2] + delta[2], result[3] + delta[3])
            
            pos = self.previous(element)
        else:
            break