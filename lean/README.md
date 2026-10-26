# Escopo das provas

`lake build` compila sete modelos de referência com Lean 4.15.0. O script
`../scripts/check-formal.py` também inspeciona a dependência de axiomas dos
teoremas principais. Não há `sorry` nem axiomas específicos do projeto.

O modelo Merkle usa termos simbólicos ilimitados e domínios distintos para
folhas e nós. Ele prova identidade de árvores válidas nesse modelo; não prova
resistência a colisões de um hash finito. O replay paralelo usa uma redução
aditiva de referência; não cobre transições arbitrárias da H-VM Rust. HLC usa
naturais, sem overflow de inteiros de máquina. Aprovação e isolamento de tool
calls são modelos puros, sem uma prova de refinamento da implementação.

O relatório gerado pelo CI registra `model_status=CHECKED` e mantém
`status=NOT_VERIFIED` para a implementação Rust. Somente testar ou compilar
esses modelos não autoriza apresentar o produto inteiro como formalmente
provado. O relatório inclui commit, versão do Lean e digest das fontes.
