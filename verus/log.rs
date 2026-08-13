use builtin::*;
use builtin_macros::*;

verus! {

pub struct Event {
    pub lsn: u64,
    pub val: u64,
}

pub struct Log {
    pub events: Vec<Event>,
}

impl Log {
    /// Invariante da estrutura de Log: todos os LSNs inseridos são estritamente crescentes.
    pub spec fn is_valid(self) -> bool {
        forall|i: int, j: int| 0 <= i && i < j && j < self.events.len() ==>
            self.events[i].lsn < self.events[j].lsn
    }

    /// Cria um novo Log vazio, provando que ele é estruturalmente válido.
    pub fn new() -> (res: Log)
        ensures res.is_valid()
    {
        Log { events: Vec::new() }
    }

    /// Executa o append-only seguro.
    /// Requer que o log de entrada seja válido e garante que o log resultante é válido.
    /// Se a inserção falhar (LSN retrocedeu), garante que o vetor original não foi poluído.
    pub fn append(&mut self, evt: Event) -> (res: bool)
        requires
            old(self).is_valid()
        ensures
            self.is_valid(),
            res ==> self.events.len() == old(self).events.len() + 1,
            !res ==> self.events == old(self).events
    {
        if self.events.len() == 0 {
            self.events.push(evt);
            true
        } else {
            let last_idx = self.events.len() - 1;
            if evt.lsn > self.events[last_idx].lsn {
                self.events.push(evt);
                true
            } else {
                false
            }
        }
    }
}

} // verus!
