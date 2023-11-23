Ошибка происходит в ходе ([[Share Download|загрузки шар]]). 
1. После добавления в трекер новых шар -> `CoindNodeData::set_best_share()`
2. В котором вызывается метод `ShareTracker::think(...)`
3. Где множественно вызывается `ShareTracker::attempt_verify(share)`
4. Из которого вызывается `Share::check(...)`, который выполняется ~0.06-0.09s

Скорость 0.06s вроде бы не страшно, но когда это вызывается в цикле для набора, например из 400 шар, скорость становится равна $$400*0.06s = 24.0s$$ 
Низкая скорость `Share::check(...)` обусловлена скоростью выполнения [[GenerateShareTransaction]] 

В ходе тестов выявил, что ~86% времени работы [[GenerateShareTransaction]], выходит на `GenerateShareTransaction::weight_amount_calculate(...)`

95% времени работы `weight_amount_calculate(...)` занимает выполнение `ShareTracker::get_cumulative_weights(...)`

По исследованию `get_cumulative_weights(...)` ~90% замедления алгоритма давёт цикл while при переборе весов:
```cpp
while (cur.sum.hash() != last)  
        {  
            if (limit == next.sum.weight.total_weight)  
            {  
                break;  
            }  
  
            if (limit > next.sum.weight.total_weight)  
            {  
                extra_ending = std::make_optional<shares::weight::weight_data>(cur.sum.share);  
                break;            
            }  
  
            cur = next;  
            if (exist(cur.sum.prev()))  
            {  
                next = get_sum_to_last(next.sum.prev());  
            } else  
            {  
                break;  
            }  
        }
```

Замедлять тут может:
	1. либо `exist(...)` -- 3%
	2. либо `next = get_sum_to_last(next.sum.prev())` -- 90%

После тестов, определил, что ~93%  от get_sum_to_last занимает:
```cpp
auto for_res = fork->get_sum(hash);
```
![[gentx_debug_time_excel.png]]
