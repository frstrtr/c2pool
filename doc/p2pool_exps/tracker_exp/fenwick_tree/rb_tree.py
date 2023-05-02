class Node:
    def __init__(self, val, color='RED'):
        self.val = val
        self.left = None
        self.right = None
        self.parent = None
        self.color = color
    
    def grandparent(self):
        if self.parent is None:
            return None
        return self.parent.parent
    
    def uncle(self):
        grandparent = self.grandparent()
        if grandparent is None:
            return None
        if self.parent is grandparent.left:
            return grandparent.right
        else:
            return grandparent.left
    
    def sibling(self):
        if self.parent is None:
            return None
        if self is self.parent.left:
            return self.parent.right
        else:
            return self.parent.left
    
    def __str__(self):
        return str(self.val)

class RedBlackTree:
    def __init__(self):
        self.root = None
    
    def insert(self, val):
        new_node = Node(val)
        if self.root is None:
            self.root = new_node
            self.root.color = 'BLACK'
        else:
            node = self.root
            while node is not None:
                if val < node.val:
                    if node.left is None:
                        node.left = new_node
                        new_node.parent = node
                        break
                    else:
                        node = node.left
                else:
                    if node.right is None:
                        node.right = new_node
                        new_node.parent = node
                        break
                    else:
                        node = node.right
            self._fix_tree(new_node)
    
    def _fix_tree(self, node):
        while node.parent is not None and node.parent.color == 'RED':
            if node.parent is node.parent.parent.left:
                uncle = node.parent.parent.right
                if uncle is not None and uncle.color == 'RED':
                    node.parent.color = 'BLACK'
                    uncle.color = 'BLACK'
                    node.parent.parent.color = 'RED'
                    node = node.parent.parent
                else:
                    if node is node.parent.right:
                        node = node.parent
                        self._left_rotate(node)
                    node.parent.color = 'BLACK'
                    node.parent.parent.color = 'RED'
                    self._right_rotate(node.parent.parent)
            else:
                uncle = node.parent.parent.left
                if uncle is not None and uncle.color == 'RED':
                    node.parent.color = 'BLACK'
                    uncle.color = 'BLACK'
                    node.parent.parent.color = 'RED'
                    node = node.parent.parent
                else:
                    if node is node.parent.left:
                        node = node.parent
                        self._right_rotate(node)
                    node.parent.color = 'BLACK'
                    node.parent.parent.color = 'RED'
                    self._left_rotate(node.parent.parent)
        self.root.color = 'BLACK'
    
    def _left_rotate(self, node):
        right_child = node.right
        node.right = right_child.left
        if right_child.left is not None:
            right_child.left.parent = node
        right_child.parent = node.parent
        if node.parent is None:
            self.root = right_child
        elif node is node.parent.left:
            node.parent.left = right_child
        else:
            node.parent.right = right_child
        right_child.left = node
        node.parent = right_child
    
    def _right_rotate(self, node):
        left_child = node.left
        node.left = left_child.right
        if left_child.right is not None:
            left_child.right.parent = node
        left_child.parent = node.parent
        if node.parent is None:
            self.root = left_child
        elif node is node.parent.right:
            node.parent.right = left_child
        else:
            node.parent.left = left_child
        left_child.right = node
        node.parent = left_child
    
    def search_range(self, start, end):
        if self.root is None:
            return 0
        return self._search_range(self.root, start, end)
    
    def _search_range(self, node, start, end):
        if node is None:
            return 0
        if node.val < start:
            return self._search_range(node.right, start, end)
        elif node.val > end:
            return self._search_range(node.left, start, end)
        else:
            return self._search_range(node.left, start, end) + node.val + self._search_range(node.right, start, end)



tree = RedBlackTree()
tree.insert(5)
tree.insert(3)
tree.insert(8)
tree.insert(7)
tree.insert(9)
tree.insert(2)
tree.insert(4)
print(tree.search_range(3, 7)) # 22